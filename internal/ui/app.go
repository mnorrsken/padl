package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ldapx"
)

// Connector opens a connection to a directory. It is a field on App rather
// than a direct call to ldapx.Connect so tests can drive the whole UI —
// including the certificate prompt and its retry — against a fake.
type Connector func(ctx context.Context, p config.Profile, pin *config.Pin, password string) (ldapx.Directory, error)

// Options are App's dependencies.
type Options struct {
	Profiles *config.Store
	Trust    *config.TrustStore
	Secrets  *config.Secrets

	// Screen is the terminal to draw on. Tests pass a tcell SimulationScreen;
	// production leaves it nil for a real one.
	Screen tcell.Screen

	// Connect defaults to ldapx.Connect.
	Connect Connector

	// InitialProfile is a profile ID to connect to at startup, from -profile.
	InitialProfile string
}

// App is the running interface.
type App struct {
	*tview.Application

	opts   Options
	screen tcell.Screen

	pages  *tview.Pages
	header *tview.TextView
	tree   *tree
	object *objectPane
	status *statusBar
	main   *tview.Flex

	// modals is the stack of open dialogs. While it is non-empty the global
	// keys stand down so the dialog owns the keyboard.
	modals []openModalPage
	// modalSeq keeps dialog page names unique, so opening the same kind of
	// dialog twice cannot collide.
	modalSeq int

	dir     ldapx.Directory
	profile config.Profile
	// generation counts connections. Work started against one connection must
	// not land on the next: a search abandoned by a disconnect can still return
	// data, and applying it would repopulate the screen from a closed session.
	generation int
	vendor     ldapx.Vendor
	root       *ldapx.RootDSE
	showAll    bool

	mu       sync.Mutex
	pending  map[int]pendingTask
	nextID   int
	spinner  *time.Ticker
	stopSpin chan struct{}
}

// New builds the interface. Nothing is drawn and no connection is made until
// Run.
func New(opts Options) *App {
	if opts.Connect == nil {
		opts.Connect = defaultConnector
	}
	a := &App{
		Application: tview.NewApplication(),
		opts:        opts,
		screen:      opts.Screen,
		pages:       tview.NewPages(),
		header:      tview.NewTextView().SetDynamicColors(true),
		tree:        newTree(),
		object:      newObjectPane(),
		status:      newStatusBar(),
		pending:     map[int]pendingTask{},
	}
	if a.screen != nil {
		a.SetScreen(a.screen)
	}

	a.header.SetBackgroundColor(colorBackground)

	panes := tview.NewFlex().
		AddItem(a.tree, 0, 2, true).
		AddItem(a.object, 0, 5, false)

	a.main = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.header, 1, 0, false).
		AddItem(panes, 0, 1, true).
		AddItem(a.status, 2, 0, false)
	a.main.SetBackgroundColor(colorBackground)

	a.pages.AddPage("main", a.main, true, true)
	a.pages.SetBackgroundColor(colorBackground)
	a.SetRoot(a.pages, true)

	a.tree.expand = func(n *tview.TreeNode, ref *node) { a.expandNode(n, ref, nil) }
	a.tree.selected = a.treeSelectionChanged
	a.object.inspect = a.inspectValue
	a.object.follow = a.jumpToDN

	a.SetInputCapture(a.globalKeys)
	a.setDisconnected("not connected")
	return a
}

func defaultConnector(ctx context.Context, p config.Profile, pin *config.Pin, password string) (ldapx.Directory, error) {
	c, err := ldapx.Connect(ctx, p, pin, password)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Run starts the event loop and does not return until the user quits.
func (a *App) Run() error {
	startup, err := a.startupAction()
	if err != nil {
		return err
	}
	// From a goroutine, not inline: QueueUpdate blocks until the event loop
	// runs the function, and the event loop is what is about to start.
	go a.QueueUpdateDraw(startup)

	defer a.disconnect()
	return a.Application.Run()
}

// startupAction decides what the first screen does: connect to the profile
// named on the command line, or open the server list.
func (a *App) startupAction() (func(), error) {
	if id := strings.TrimSpace(a.opts.InitialProfile); id != "" {
		p, ok := a.opts.Profiles.Get(id)
		if !ok {
			return nil, fmt.Errorf("no profile with id %q", id)
		}
		return func() { a.connect(p) }, nil
	}
	if len(a.opts.Profiles.List()) == 0 {
		return func() {
			a.status.info("No servers configured yet — press p, then a, to add one.")
			a.openProfiles()
		}, nil
	}
	return func() { a.openProfiles() }, nil
}

// ---------------------------------------------------------------- background

// taskGroup names a class of background work. Starting a task in a group
// abandons the one already running in it, which is what makes arrow-key
// scrolling through the tree cheap: only the newest entry read survives.
type taskGroup string

const (
	// groupNone is for work that must not be displaced by anything else,
	// notably a child expansion the user explicitly asked for.
	groupNone taskGroup = ""
	// groupEntry is the object-pane read, superseded on every cursor move.
	groupEntry taskGroup = "entry"
)

type pendingTask struct {
	group  taskGroup
	cancel context.CancelFunc
}

// task runs work off the UI thread and applies its result back on it.
//
// Every directory call goes through here. tview draws from a single goroutine,
// so a search run inline would freeze the terminal until the server answered —
// and on a slow directory that is the difference between a tool that feels
// alive and one that looks hung.
func (a *App) task(group taskGroup, label string, work func(ctx context.Context) (func(), error)) {
	ctx, cancel := context.WithCancel(context.Background())
	// Captured on the UI thread here and compared on the UI thread below, so
	// no lock is needed.
	gen := a.generation

	a.mu.Lock()
	var superseded []context.CancelFunc
	if group != groupNone {
		for id, p := range a.pending {
			if p.group == group {
				superseded = append(superseded, p.cancel)
				delete(a.pending, id)
			}
		}
	}
	id := a.nextID
	a.nextID++
	a.pending[id] = pendingTask{group: group, cancel: cancel}
	count := len(a.pending)
	a.mu.Unlock()

	for _, c := range superseded {
		c()
	}

	if count == 1 {
		a.startSpinner()
	}
	if label != "" {
		a.status.info("%s", label)
	}

	go func() {
		apply, err := work(ctx)

		a.mu.Lock()
		// A superseded task has already been removed from the map; leave the
		// map alone in that case so it cannot clobber a newer entry.
		_, stillOurs := a.pending[id]
		if stillOurs {
			delete(a.pending, id)
		}
		remaining := len(a.pending)
		a.mu.Unlock()
		cancel()

		if remaining == 0 {
			a.stopSpinner()
		}
		if !stillOurs {
			// Superseded by a newer task in the same group: its result is the
			// one the user is waiting for, so drop this one silently.
			return
		}

		a.QueueUpdateDraw(func() {
			if gen != a.generation {
				// The connection this was started on is gone. Its answer, and
				// its failure, are both irrelevant now.
				return
			}
			switch {
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				a.status.warn("cancelled")
			case err != nil:
				a.status.errorf("%v", err)
			default:
				if label != "" {
					a.status.info("")
				}
			}
			if apply != nil {
				apply()
			}
		})
	}()
}

// cancelPending abandons everything in flight, which is what Esc does.
func (a *App) cancelPending() bool {
	a.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(a.pending))
	for _, p := range a.pending {
		cancels = append(cancels, p.cancel)
	}
	a.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	return len(cancels) > 0
}

var spinnerFrames = []string{"|", "/", "-", "\\"}

func (a *App) startSpinner() {
	a.mu.Lock()
	if a.spinner != nil {
		a.mu.Unlock()
		return
	}
	ticker := time.NewTicker(120 * time.Millisecond)
	stop := make(chan struct{})
	a.spinner, a.stopSpin = ticker, stop
	a.mu.Unlock()

	go func() {
		frame := 0
		for {
			select {
			case <-stop:
				a.QueueUpdateDraw(func() { a.status.setSpinner("") })
				return
			case <-ticker.C:
				f := spinnerFrames[frame%len(spinnerFrames)]
				frame++
				a.QueueUpdateDraw(func() { a.status.setSpinner(f) })
			}
		}
	}()
}

func (a *App) stopSpinner() {
	a.mu.Lock()
	ticker, stop := a.spinner, a.stopSpin
	a.spinner, a.stopSpin = nil, nil
	a.mu.Unlock()
	if ticker != nil {
		ticker.Stop()
		close(stop)
	}
}

// -------------------------------------------------------------------- modals

// openModalPage is one entry on the dialog stack, remembering what had focus
// when it opened.
type openModalPage struct {
	name string
	// restore is the primitive to hand the keyboard back to on close. Closing a
	// value inspector must return to the object pane the user opened it from,
	// not dump them back in the tree.
	restore tview.Primitive
}

func (a *App) openModal(p tview.Primitive) string {
	a.modalSeq++
	name := fmt.Sprintf("modal-%d", a.modalSeq)
	a.modals = append(a.modals, openModalPage{name: name, restore: a.GetFocus()})
	a.pages.AddPage(name, p, true, true)
	a.SetFocus(p)
	return name
}

func (a *App) closeModal(name string) {
	a.pages.RemovePage(name)

	var restore tview.Primitive
	for i, m := range a.modals {
		if m.name == name {
			restore = m.restore
			a.modals = append(a.modals[:i], a.modals[i+1:]...)
			break
		}
	}
	if restore == nil {
		restore = a.tree
	}
	a.SetFocus(restore)
	a.refreshHints()
}

func (a *App) modalOpen() bool { return len(a.modals) > 0 }

func (a *App) showError(title string, err error) {
	name := ""
	name = a.openModal(messageBox(title, err.Error(), colorError, func() { a.closeModal(name) }))
}

// ------------------------------------------------------------------ keys

func (a *App) globalKeys(ev *tcell.EventKey) *tcell.EventKey {
	// A dialog owns the keyboard while it is up; global shortcuts firing
	// underneath a modal is a classic way to lose typed input.
	if a.modalOpen() {
		return ev
	}

	switch ev.Key() {
	case tcell.KeyEscape:
		if a.cancelPending() {
			return nil
		}
		return ev
	case tcell.KeyTab:
		a.focusNext()
		return nil
	case tcell.KeyBacktab:
		a.focusNext()
		return nil
	case tcell.KeyCtrlC:
		return ev
	}

	switch ev.Rune() {
	case 'q':
		a.Stop()
		return nil
	case '?':
		a.openHelp()
		return nil
	case 'p':
		a.openProfiles()
		return nil
	case 'c':
		a.toggleConnection()
		return nil
	}

	if a.GetFocus() == a.tree {
		return a.treeKeys(ev)
	}
	return a.objectKeys(ev)
}

func (a *App) treeKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyRight:
		a.tree.expandCurrent()
		return nil
	case tcell.KeyLeft:
		if !a.tree.collapseCurrent() {
			// Already closed: step up to the parent, the way a file tree does.
			return tcell.NewEventKey(tcell.KeyRune, 'K', tcell.ModNone)
		}
		return nil
	}

	switch ev.Rune() {
	case 'j':
		return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
	case 'k':
		return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
	case 'l':
		a.tree.expandCurrent()
		return nil
	case 'h':
		if !a.tree.collapseCurrent() {
			return tcell.NewEventKey(tcell.KeyRune, 'K', tcell.ModNone)
		}
		return nil
	case 'r':
		a.reloadCurrentNode()
		return nil
	case 'y':
		a.copyToClipboard("DN", a.tree.currentDN())
		return nil
	case 'a':
		a.toggleShowAllContexts()
		return nil
	}
	return ev
}

func (a *App) objectKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Rune() {
	case 'j':
		return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
	case 'k':
		return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
	case 'o':
		a.toggleOperational()
		return nil
	case 'y':
		if r, ok := a.object.currentValue(); ok {
			a.copyToClipboard(r.attr, r.value.Text)
		}
		return nil
	}
	return ev
}

func (a *App) focusNext() {
	if a.GetFocus() == a.tree {
		a.SetFocus(a.object.table)
	} else {
		a.SetFocus(a.tree)
	}
	a.refreshHints()
}

func (a *App) refreshHints() {
	common := "tab pane · p servers · c connect · ? help · q quit"
	if a.modalOpen() {
		a.status.setKeys("esc close dialog")
		return
	}
	if a.GetFocus() == a.tree {
		a.status.setKeys("[tree] enter expand · r reload · y copy dn · a all contexts · " + common)
		return
	}
	a.status.setKeys("[object] enter inspect · o operational · y copy value · " + common)
}

// copyToClipboard uses the terminal's own OSC 52 clipboard, which is the only
// mechanism that also works when PADL is running on the far end of an ssh
// session. Terminals are free to ignore it, so the status line says what was
// copied rather than claiming success outright.
func (a *App) copyToClipboard(what, value string) {
	if value == "" {
		a.status.warn("nothing to copy")
		return
	}
	if a.screen == nil {
		a.status.warn("no clipboard available")
		return
	}
	a.screen.SetClipboard([]byte(value))
	a.status.ok("copied %s: %s", what, value)
}

// --------------------------------------------------------------- connection

func (a *App) toggleConnection() {
	if a.dir != nil {
		a.disconnect()
		a.setDisconnected("disconnected")
		return
	}
	a.openProfiles()
}

func (a *App) disconnect() {
	if a.dir == nil {
		return
	}
	// Abandon anything in flight and retire this generation, so a search that
	// is already on its way back cannot draw itself onto the next screen.
	a.cancelPending()
	a.generation++
	_ = a.dir.Close()
	a.dir = nil
	a.root = nil
}

// connect resolves the password, prompting if it is not on file, then dials.
func (a *App) connect(p config.Profile) {
	password, err := a.opts.Secrets.Lookup(p)
	if err == nil {
		a.dial(p, password, false, 0)
		return
	}
	if !errors.Is(err, config.ErrPromptRequired) {
		a.showError("Password", err)
		return
	}

	note := ""
	var unavailable *config.KeyringUnavailableError
	if errors.As(err, &unavailable) {
		// Say why the keychain is out of the picture; on a headless box an
		// unexplained password box just looks broken.
		note = unavailable.Error()
	}

	name := ""
	name = a.openModal(passwordPrompt(
		p.Display(), p.BindDN, note,
		p.PasswordRef == config.PasswordKeyring && unavailable == nil,
		func(password string, save bool) {
			a.closeModal(name)
			a.dial(p, password, save, 0)
		},
		func() {
			a.closeModal(name)
			a.status.warn("connect cancelled")
		},
	))
}

// maxTrustRetries bounds the pin-and-retry loop. One retry is all a correct
// flow ever needs; the bound is there so a server that somehow keeps failing
// verification cannot spin the prompt forever.
const maxTrustRetries = 2

// dial opens the connection, handling the certificate prompt and its retry.
func (a *App) dial(p config.Profile, password string, savePassword bool, attempt int) {
	var pin *config.Pin
	if existing, ok := a.opts.Trust.Get(p.ID); ok {
		pin = &existing
	}

	a.task(groupNone, fmt.Sprintf("connecting to %s…", p.Addr()), func(ctx context.Context) (func(), error) {
		dir, err := a.opts.Connect(ctx, p, pin, password)
		if err != nil {
			if cte, ok := ldapx.AsCertTrustError(err); ok {
				// Not an error to report: it is a question for the operator.
				return func() { a.promptTrust(p, cte, password, savePassword, attempt) }, nil
			}
			if errors.Is(err, context.Canceled) {
				return nil, err
			}
			// A failed connect gets a dialog as well as the status line. The
			// status bar is one row, and the useful part of a bind failure is
			// usually the server's diagnostic at the end of a long message.
			failed := err
			return func() { a.showError(" Connect failed ", failed) }, err
		}
		return func() { a.adopt(p, dir, password, savePassword) }, nil
	})
}

// promptTrust asks the operator about a certificate and, on acceptance, pins it
// and dials again. The retry is why ldapx.Connect keeps no state until it fully
// succeeds — this is its second call with the same arguments plus a pin.
func (a *App) promptTrust(p config.Profile, cte *ldapx.CertTrustError, password string, savePassword bool, attempt int) {
	if attempt >= maxTrustRetries {
		a.status.errorf("%v", cte)
		return
	}
	name := ""
	name = a.openModal(certPrompt(cte,
		func() {
			a.closeModal(name)
			if err := a.opts.Trust.Set(p.ID, cte.Pin()); err != nil {
				a.showError("Trust store", err)
				return
			}
			a.status.ok("pinned %s", cte.Fingerprint)
			a.dial(p, password, savePassword, attempt+1)
		},
		func() {
			a.closeModal(name)
			a.status.warn("certificate rejected — not connected")
		},
	))
}

// adopt takes ownership of a fresh connection and repoints the UI at it.
func (a *App) adopt(p config.Profile, dir ldapx.Directory, password string, savePassword bool) {
	a.disconnect()
	a.generation++
	a.dir = dir
	a.profile = p
	a.showAll = false

	if savePassword {
		if err := a.opts.Secrets.Store(p, password); err != nil {
			// Not fatal: the connection is up, the password just did not stick.
			a.status.warn("connected, but the password was not saved: %v", err)
		}
	}

	if c, ok := dir.(*ldapx.Client); ok {
		a.vendor = c.Vendor()
		a.root = c.Root()
	} else {
		a.vendor = ldapx.VendorGeneric
		a.root = nil
	}

	a.loadBases()
	a.renderHeader()
	a.refreshHints()
	a.SetFocus(a.tree)
}

// loadBases fills the tree roots. When the root DSE was not usable the profile's
// base DN is the fallback, and when there is neither the message says which
// knob to turn instead of leaving an empty pane.
func (a *App) loadBases() {
	root := a.root
	if root == nil {
		a.task(groupNone, "reading root DSE…", func(ctx context.Context) (func(), error) {
			r, err := a.dir.RootDSE(ctx)
			if err != nil {
				return nil, err
			}
			return func() {
				a.root = r
				a.loadBases()
			}, nil
		})
		return
	}

	bases := root.Bases(a.profile.BaseDN, a.showAll)
	if len(bases) == 0 {
		a.tree.clear(a.profile.Display())
		a.object.setBases(nil)
		a.object.clear("")
		a.status.warn("the server published no naming contexts — set a base DN on the profile (p, then e)")
		return
	}
	a.tree.reset(bases, a.profile.Display())
	a.object.setBases(bases)
	a.object.clear("select an entry")
	// Open the first base straight away; an unexpanded root is a wasted screen.
	if children := a.tree.root.GetChildren(); len(children) > 0 {
		a.tree.toggle(children[0])
	}
}

func (a *App) setDisconnected(reason string) {
	a.vendor = ldapx.VendorGeneric
	a.root = nil
	a.tree.clear("Directory")
	a.object.setBases(nil)
	a.object.clear(reason)
	a.renderHeader()
	a.refreshHints()
}

func (a *App) renderHeader() {
	if a.dir == nil {
		a.header.SetText(fmt.Sprintf("[%s]PADL[-]  [%s]not connected — press p to pick a server[-]",
			tag(colorAccent), tag(colorDim)))
		return
	}
	contexts := ""
	if a.root != nil && len(a.root.Bases(a.profile.BaseDN, true)) > len(a.root.Bases(a.profile.BaseDN, false)) {
		contexts = fmt.Sprintf("  [%s](a: show all contexts)[-]", tag(colorDim))
	}
	a.header.SetText(fmt.Sprintf("[%s]PADL[-]  %s  [%s]%s[-]  [%s]%s[-]%s",
		tag(colorAccent), tview.Escape(a.profile.Display()),
		tag(colorDim), tview.Escape(a.profile.URL()),
		tag(colorOK), a.vendor.String(),
		contexts))
}

func (a *App) toggleShowAllContexts() {
	if a.dir == nil || a.root == nil {
		return
	}
	a.showAll = !a.showAll
	a.loadBases()
	a.renderHeader()
}

// ---------------------------------------------------------------- tree logic

// expandNode fetches a node's children. then, if given, runs once they are in
// place — which is how the jump-to-DN walk steps down one level at a time.
func (a *App) expandNode(n *tview.TreeNode, ref *node, then func()) {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	ref.loading = true
	a.tree.markLoading(n)

	dn := ref.dn
	limit := a.profile.Limit()
	a.task(groupNone, fmt.Sprintf("listing %s…", dn), func(ctx context.Context) (func(), error) {
		entries, truncated, err := a.dir.Children(ctx, dn, limit)
		if err != nil {
			return func() { a.tree.failLoad(n, ref) }, err
		}
		return func() {
			a.tree.setChildren(n, ref, entries, truncated)
			if truncated {
				a.status.warn("%s has more than %d children — only the first %d are shown", dn, limit, limit)
			}
			if then != nil {
				then()
			}
		}, nil
	})
}

func (a *App) reloadCurrentNode() {
	n := a.tree.GetCurrentNode()
	ref := refOf(n)
	if ref == nil || a.dir == nil {
		return
	}
	if ref.kind == nodePlaceholder || ref.kind == nodeMore {
		return
	}
	ref.loaded = false
	ref.loading = false
	a.expandNode(n, ref, nil)
}

// treeSelectionChanged loads the highlighted entry into the object pane.
//
// Arrow-key scrolling fires this on every row, so the previous read is
// abandoned rather than left to land after the user has moved on.
func (a *App) treeSelectionChanged(ref *node) {
	if a.dir == nil || ref == nil {
		return
	}
	switch ref.kind {
	case nodePlaceholder:
		return
	case nodeMore:
		a.object.clear("this container has more children than are shown")
		return
	}
	// No blanket cancel here: the entry read supersedes only the previous
	// entry read, so scrolling past a container does not abandon the child
	// expansion the user just asked for.
	a.loadEntry(ref.dn)
}

func (a *App) loadEntry(dn string) {
	if dn == "" {
		a.object.clear("select an entry")
		return
	}
	a.object.setBusy(dn)
	operational := a.object.showOperational()
	a.task(groupEntry, "", func(ctx context.Context) (func(), error) {
		e, err := a.dir.Entry(ctx, dn, operational)
		if err != nil {
			return func() { a.object.clear(fmt.Sprintf("could not read %s", dn)) }, err
		}
		return func() { a.object.show(e) }, nil
	})
}

func (a *App) toggleOperational() {
	if a.dir == nil {
		return
	}
	a.object.setOperational(!a.object.showOperational())
	if a.object.showOperational() {
		a.status.info("showing operational attributes")
	} else {
		a.status.info("hiding operational attributes")
	}
	a.loadEntry(a.tree.currentDN())
}

func (a *App) inspectValue(attr string, v ldapx.Value) {
	name := ""
	name = a.openModal(valueInspector(attr, v, func() { a.closeModal(name) }))
}

// ------------------------------------------------------------------ dialogs

func (a *App) openHelp() {
	name := ""
	name = a.openModal(helpView(func() { a.closeModal(name) }))
}

func (a *App) openProfiles() {
	name := ""
	name = a.openModal(profileList(a.opts.Profiles.List(), profileListActions{
		connect: func(p config.Profile) {
			a.closeModal(name)
			a.connect(p)
		},
		edit: func(p config.Profile) { a.openProfileForm(p, false) },
		add:  func() { a.openProfileForm(config.NewProfile(), true) },
		remove: func(p config.Profile) {
			a.confirmDelete(p, func() {
				a.closeModal(name)
				a.openProfiles()
			})
		},
		close: func() { a.closeModal(name) },
	}))
}

func (a *App) openProfileForm(p config.Profile, isNew bool) {
	name := ""
	name = a.openModal(profileForm(p, isNew,
		func(saved config.Profile) {
			if err := a.opts.Profiles.Put(saved); err != nil {
				a.showError("Save profile", err)
				return
			}
			a.closeModal(name)
			// Reopen the list so the change is visible straight away.
			a.reopenProfiles()
			a.status.ok("saved %s", saved.Display())
		},
		func() { a.closeModal(name) },
	))
}

// reopenProfiles rebuilds the server list under whatever dialog was on top of
// it, since tview lists are built once from a snapshot.
func (a *App) reopenProfiles() {
	for len(a.modals) > 0 {
		a.closeModal(a.modals[len(a.modals)-1].name)
	}
	a.openProfiles()
}

func (a *App) confirmDelete(p config.Profile, done func()) {
	name := ""
	name = a.openModal(confirmBox(" Delete server ",
		fmt.Sprintf("Delete profile %q?\n\nIts pinned certificate and saved password go with it.", p.Display()),
		func() {
			a.closeModal(name)
			if err := a.opts.Profiles.Delete(p.ID); err != nil {
				a.showError("Delete profile", err)
				return
			}
			// The pin and the keychain entry are keyed by profile ID, so
			// leaving them behind would silently attach to a later profile
			// that happens to reuse the name.
			if err := a.opts.Trust.Delete(p.ID); err != nil {
				a.status.warn("profile deleted, but its pinned certificate remains: %v", err)
			}
			if err := a.opts.Secrets.Forget(p); err != nil {
				a.status.warn("profile deleted, but its saved password remains: %v", err)
			}
			a.status.ok("deleted %s", p.Display())
			done()
		},
		func() { a.closeModal(name) },
	))
}

// ------------------------------------------------------------ jump to a DN

// jumpToDN moves the tree cursor to dn, opening whatever is closed on the way.
//
// This is what makes group membership navigable: member, memberOf, manager and
// the rest all hold DNs, and reading one only to type it back in by hand is the
// slowest part of using a directory browser.
func (a *App) jumpToDN(dn string) {
	if a.dir == nil {
		return
	}
	bases := a.tree.bases()
	base := ldapx.BestBase(dn, bases)
	if base == "" {
		// Most often an AD entry in the Configuration partition, which is
		// hidden by default — so say which key reveals it.
		a.status.warn("%s is not under any naming context shown — press a to show them all", dn)
		return
	}
	path := ldapx.PathFrom(base, dn)
	if len(path) == 0 {
		a.status.warn("cannot work out where %s sits in the tree", dn)
		return
	}
	a.status.info("going to %s…", dn)
	a.walkTo(path, 0)
}

// walkTo steps down one level of a jump, expanding as it goes.
//
// Each expansion is a round trip, so this cannot be a loop: every step that has
// to load resumes the walk from expandNode's completion callback.
func (a *App) walkTo(path []string, i int) {
	if i >= len(path) {
		return
	}
	target := path[i]

	n := a.tree.find(target)
	if n == nil {
		a.reportJumpMiss(path, i)
		return
	}

	if i == len(path)-1 {
		a.tree.SetCurrentNode(n)
		a.SetFocus(a.tree)
		a.refreshHints()
		a.status.ok("%s", target)
		return
	}

	ref := refOf(n)
	if ref == nil {
		a.reportJumpMiss(path, i)
		return
	}
	if ref.loaded {
		n.SetExpanded(true)
		a.walkTo(path, i+1)
		return
	}
	// Not loaded yet. Expand it — deliberately bypassing the is-this-a-leaf
	// check, since an entry on the path to another one demonstrably has
	// children whatever the server claimed.
	a.expandNode(n, ref, func() { a.walkTo(path, i+1) })
}

// reportJumpMiss explains a jump that ran out of tree. The parent's state says
// which of the two reasons it was, and they call for different fixes.
func (a *App) reportJumpMiss(path []string, i int) {
	missing := path[i]
	if i == 0 {
		a.status.errorf("%s is not in the tree", missing)
		return
	}
	parent := path[i-1]
	if p := a.tree.find(parent); p != nil {
		if ref := refOf(p); ref != nil && ref.truncated {
			a.status.errorf("%s was not among the first %d children of %s — raise the profile's child limit",
				missing, ref.childCount, parent)
			return
		}
	}
	a.status.errorf("%s does not exist under %s", missing, parent)
}
