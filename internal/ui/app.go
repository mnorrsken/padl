package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ldapx"
	"github.com/mnorrsken/padl/internal/ldif"
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

	// Screen is the terminal to draw on. Tests pass a tcell SimulationScreen.
	// Production leaves it nil so tview opens the real terminal itself — which
	// is the only path that reports a failure to open it, see New.
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

	// left swaps the tree for the search results without disturbing the rest of
	// the layout.
	left    *tview.Pages
	results *resultsPane
	search  *searchBar
	// searching is true while the filter bar is open, so the global keys stand
	// down and let it have the keyboard.
	searching bool

	// modals is the stack of open dialogs. While it is non-empty the global
	// keys stand down so the dialog owns the keyboard.
	modals []openModalPage
	// modalSeq keeps dialog page names unique, so opening the same kind of
	// dialog twice cannot collide.
	modalSeq int

	dir     ldapx.Directory
	profile config.Profile
	// back and forward are the visited-entry history, the way a browser keeps
	// one. Only deliberate jumps are recorded — following a link, a search
	// result, a bookmark, go-to-DN — not every cursor move, because scrolling
	// through a container is reading rather than navigating.
	back    []string
	forward []string
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
		left:        tview.NewPages(),
		results:     newResultsPane(),
		search:      newSearchBar(),
		pending:     map[int]pendingTask{},
	}
	if a.screen != nil {
		a.SetScreen(a.screen)
	}
	// When tview opens the terminal itself, this is how the screen is obtained:
	// there is no getter for it, and it is needed for the OSC 52 clipboard.
	// Creating it here instead and handing it to SetScreen would look tidier
	// but loses the Init error — SetScreen discards it, and the failure then
	// surfaces as a nil-channel panic on shutdown rather than a message.
	a.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		a.screen = screen
		return false
	})

	a.header.SetBackgroundColor(colorBackground)

	a.left.AddPage("tree", a.tree, true, true)
	a.left.AddPage("results", a.results, true, false)
	a.left.SetBackgroundColor(colorBackground)

	panes := tview.NewFlex().
		AddItem(a.left, 0, 2, true).
		AddItem(a.object, 0, 5, false)

	a.main = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.header, 1, 0, false).
		AddItem(panes, 0, 1, true).
		AddItem(a.search, 2, 0, false).
		AddItem(a.status, 2, 0, false)
	// The filter bar only takes space while it is open.
	a.main.ResizeItem(a.search, 0, 0)
	a.main.SetBackgroundColor(colorBackground)

	a.pages.AddPage("main", a.main, true, true)
	a.pages.SetBackgroundColor(colorBackground)
	a.SetRoot(a.pages, true)

	a.tree.expand = func(n *tview.TreeNode, ref *node) { a.expandNode(n, ref, nil) }
	a.tree.loadMore = a.loadMoreChildren
	a.tree.selected = a.treeSelectionChanged
	a.object.inspect = a.inspectValue
	a.object.follow = a.jumpToDN

	a.search.run = a.runSearch
	a.search.cancel = a.closeSearchBar
	a.results.selected = a.loadEntry
	a.results.chosen = a.jumpFromResults
	a.results.more = a.loadMoreResults
	a.results.closed = a.closeResults

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
	// A dialog or the filter bar owns the keyboard while it is up; global
	// shortcuts firing underneath one is a classic way to lose typed input.
	if a.modalOpen() || a.searching {
		return ev
	}

	switch ev.Key() {
	case tcell.KeyEscape:
		if a.cancelPending() {
			return nil
		}
		if a.showingResults() {
			a.closeResults()
			return nil
		}
		return ev
	case tcell.KeyTab:
		a.focusNext()
		return nil
	case tcell.KeyBacktab:
		a.focusNext()
		return nil
	case tcell.KeyLeft:
		// Alt-left and alt-right are the browser bindings; the pane keys keep
		// plain arrows.
		if ev.Modifiers()&tcell.ModAlt != 0 {
			a.goBack()
			return nil
		}
	case tcell.KeyRight:
		if ev.Modifiers()&tcell.ModAlt != 0 {
			a.goForward()
			return nil
		}
	case tcell.KeyCtrlC:
		return ev
	}

	switch ev.Rune() {
	case 'q':
		a.Stop()
		return nil
	case '/':
		a.openSearch()
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
	case 'B':
		a.openBookmarks()
		return nil
	case 'g':
		a.promptJumpToDN()
		return nil
	case '<':
		// The same as alt-left, for layouts where alt-arrow is awkward or the
		// terminal eats it.
		a.goBack()
		return nil
	case '>':
		a.goForward()
		return nil
	}

	switch a.GetFocus() {
	case a.tree:
		return a.treeKeys(ev)
	case a.results:
		return a.resultsKeys(ev)
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
	case 'b':
		a.toggleBookmark()
		return nil
	case 'L':
		a.copyEntryAsLDIF()
		return nil
	case 'E':
		a.exportSubtree()
		return nil
	}
	return ev
}

func (a *App) resultsKeys(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Rune() == 'y' {
		i := a.results.GetCurrentItem()
		if i >= 0 && i < len(a.results.entries) {
			a.copyToClipboard("DN", a.results.entries[i].DN)
		}
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
	case 'L':
		a.copyEntryAsLDIF()
		return nil
	}
	return ev
}

func (a *App) focusNext() {
	left := a.leftPrimitive()
	if a.GetFocus() == left {
		a.SetFocus(a.object.table)
	} else {
		a.SetFocus(left)
	}
	a.refreshHints()
}

// leftPrimitive is whichever of the tree or the results list is showing.
func (a *App) leftPrimitive() tview.Primitive {
	if a.showingResults() {
		return a.results
	}
	return a.tree
}

func (a *App) refreshHints() {
	common := "tab pane · / search · g goto · < > history · B bookmarks · p servers · ? help · q quit"
	switch {
	case a.modalOpen():
		a.status.setKeys("esc close dialog")
	case a.searching:
		a.status.setKeys("[search] words search several attributes · ( starts a raw filter · ctrl-s scope · ↑↓ history · enter run · esc cancel")
	case a.GetFocus() == a.results:
		a.status.setKeys("[results] enter go to it in the tree · y copy dn · esc back · " + common)
	case a.GetFocus() == a.tree:
		a.status.setKeys("[tree] enter expand · r reload · y copy dn · b bookmark · L ldif · E export · " + common)
	default:
		a.status.setKeys("[object] enter follow/inspect · o operational · y copy value · L ldif · " + common)
	}
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
	a.back, a.forward = nil, nil

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

	a.left.SwitchToPage("tree")
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
	a.left.SwitchToPage("tree")
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
	a.left.SwitchToPage("tree")
	a.loadBases()
	a.renderHeader()
}

// ---------------------------------------------------------------- tree logic

// expandNode fetches a node's first page of children. then, if given, runs once
// they are in place — which is how the jump-to-DN walk steps down one level at
// a time.
func (a *App) expandNode(n *tview.TreeNode, ref *node, then func()) {
	a.fetchChildren(n, ref, ldapx.PageRequest{Size: a.profile.Limit()}, false, then)
}

// loadMoreChildren continues a paged listing from the "load more" row. n is
// that row; its parent is the container being listed.
func (a *App) loadMoreChildren(more *tview.TreeNode, ref *node) {
	parent := a.tree.parentOf(more)
	if parent == nil {
		return
	}
	parentRef := refOf(parent)
	if parentRef == nil || parentRef.loading || len(parentRef.cookie) == 0 {
		return
	}
	a.fetchChildren(parent, parentRef,
		ldapx.PageRequest{Size: a.profile.Limit(), Cookie: parentRef.cookie}, true, nil)
}

// fetchChildren loads one page of a container's children.
func (a *App) fetchChildren(n *tview.TreeNode, ref *node, req ldapx.PageRequest, appendPage bool, then func()) {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	ref.loading = true
	if !appendPage {
		a.tree.markLoading(n)
	}

	dn := ref.dn
	a.task(groupNone, fmt.Sprintf("listing %s…", dn), func(ctx context.Context) (func(), error) {
		page, err := a.dir.Children(ctx, dn, req)
		if err != nil {
			return func() {
				ref.loading = false
				if !appendPage {
					a.tree.failLoad(n, ref)
				}
			}, err
		}
		return func() {
			a.tree.setChildren(n, ref, page, appendPage)
			switch {
			case page.Truncated:
				a.status.warn("%s: showing the first %d children; this server has no paged results, so raise the profile's child limit to see more",
					dn, ref.childCount)
			case page.More():
				a.status.info("%s: %d children so far, more available", dn, ref.childCount)
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

// jumpMaxPages bounds how far a jump will page through a container looking for
// its target. A jump should be willing to work for it, but not to walk a
// hundred-thousand-entry container to the end while the user waits.
const jumpMaxPages = 20

// walk is one in-progress jump down the tree.
type walk struct {
	path []string
	// index is the step being resolved.
	index int
	// pages counts what has been loaded looking for the current step, so a
	// container far larger than expected does not page forever.
	pages int
}

// jumpToDN moves the tree cursor to dn, opening whatever is closed on the way.
//
// This is what makes group membership navigable: member, memberOf, manager and
// the rest all hold DNs, and reading one only to type it back in by hand is the
// slowest part of using a directory browser.
func (a *App) jumpToDN(dn string) { a.navigateTo(dn, true) }

// navigateTo goes to a DN. record is false when the move is itself a history
// step, so going back does not push what it is coming from.
func (a *App) navigateTo(dn string, record bool) {
	if a.dir == nil {
		return
	}
	base := ldapx.BestBase(dn, a.tree.bases())
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
	if record {
		a.recordJump(dn)
	}
	a.status.info("going to %s…", dn)
	a.walkTo(&walk{path: path})
}

// walkTo steps down one level of a jump, expanding as it goes.
//
// Each expansion is a round trip, so this cannot be a loop: every step that has
// to load resumes the walk from fetchChildren's completion callback.
func (a *App) walkTo(w *walk) {
	if w.index >= len(w.path) {
		return
	}
	target := w.path[w.index]

	n := a.tree.find(target)
	if n == nil {
		// Not among the children loaded so far. If the parent has more pages,
		// the entry may simply be further down: keep pulling pages rather than
		// declaring it missing, which is the difference between a link that
		// works and one that works only for small containers.
		if a.pageTowards(w) {
			return
		}
		a.jumpMissed(w)
		return
	}

	if w.index == len(w.path)-1 {
		a.tree.SetCurrentNode(n)
		a.SetFocus(a.tree)
		a.refreshHints()
		a.status.ok("%s", target)
		return
	}

	ref := refOf(n)
	if ref == nil {
		a.jumpMissed(w)
		return
	}
	if ref.loaded {
		n.SetExpanded(true)
		a.walkTo(&walk{path: w.path, index: w.index + 1})
		return
	}
	// Not loaded yet. Expand it — deliberately bypassing the is-this-a-leaf
	// check, since an entry on the path to another one demonstrably has
	// children whatever the server claimed.
	a.fetchChildren(n, ref, ldapx.PageRequest{Size: a.profile.Limit()}, false, func() {
		a.walkTo(&walk{path: w.path, index: w.index + 1})
	})
}

// pageTowards loads another page of the parent container and resumes the walk,
// reporting whether it did. It stops at jumpMaxPages so an enormous container
// cannot hold a jump open indefinitely.
func (a *App) pageTowards(w *walk) bool {
	if w.index == 0 || w.pages >= jumpMaxPages {
		return false
	}
	parent := a.tree.find(w.path[w.index-1])
	if parent == nil {
		return false
	}
	ref := refOf(parent)
	if ref == nil || ref.loading || len(ref.cookie) == 0 {
		return false
	}

	next := &walk{path: w.path, index: w.index, pages: w.pages + 1}
	a.fetchChildren(parent, ref,
		ldapx.PageRequest{Size: a.profile.Limit(), Cookie: ref.cookie}, true,
		func() { a.walkTo(next) })
	return true
}

// jumpMissed handles a target the tree cannot show.
//
// Rather than leaving the cursor wherever it happened to be — which reads as
// the jump having done nothing at all — the entry is read on its own and put in
// the object pane. You still see what you asked for; it just has no row in the
// tree yet.
func (a *App) jumpMissed(w *walk) {
	target := w.path[len(w.path)-1]
	missing := w.path[w.index]

	if w.index == 0 {
		a.status.errorf("%s is not in the tree", missing)
		return
	}

	parentDN := w.path[w.index-1]
	if p := a.tree.find(parentDN); p != nil {
		if ref := refOf(p); ref != nil {
			switch {
			case len(ref.cookie) > 0:
				a.showEntryOutsideTree(target, fmt.Sprintf(
					"%s is more than %d pages into %s — showing it on its own",
					missing, jumpMaxPages, parentDN))
				return
			case ref.truncated:
				a.showEntryOutsideTree(target, fmt.Sprintf(
					"%s is not in the %d children of %s this server would return — showing it on its own",
					missing, ref.childCount, parentDN))
				return
			}
		}
	}
	// The parent is fully listed and the entry is genuinely not under it.
	a.status.errorf("%s does not exist under %s", missing, parentDN)
}

// showEntryOutsideTree loads an entry the tree cannot reach into the object
// pane anyway.
func (a *App) showEntryOutsideTree(dn, why string) {
	a.loadEntry(dn)
	a.status.warn("%s", why)
}

// -------------------------------------------------------------------- search

// openSearch drops the filter bar in, primed to search under whatever the tree
// has selected. Searching from where you are standing is nearly always what is
// wanted; the base is shown so it is never a guess.
func (a *App) openSearch() {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	base := a.searchBase()
	if base == "" {
		a.status.warn("nothing selected to search under")
		return
	}
	a.searching = true
	a.search.open(base, a.vendor)
	a.main.ResizeItem(a.search, 2, 0)
	a.SetFocus(a.search.input)
	a.status.setKeys("[search] words search several attributes · ( starts a raw filter · ctrl-s scope · ↑↓ history · enter run · esc cancel")
}

// searchBase is the DN a new search starts from: the selected entry, or the
// naming context it sits under when the cursor is on a results row.
func (a *App) searchBase() string {
	if dn := a.tree.currentDN(); dn != "" {
		return dn
	}
	if bases := a.tree.bases(); len(bases) > 0 {
		return bases[0]
	}
	return ""
}

func (a *App) closeSearchBar() {
	a.searching = false
	a.main.ResizeItem(a.search, 0, 0)
	if a.showingResults() {
		a.SetFocus(a.results)
	} else {
		a.SetFocus(a.tree)
	}
	a.refreshHints()
}

func (a *App) showingResults() bool {
	name, _ := a.left.GetFrontPage()
	return name == "results"
}

func (a *App) runSearch(q ldapx.Query) {
	a.closeSearchBar()
	a.fetchResults(q, ldapx.PageRequest{Size: a.profile.Limit()}, false)
}

func (a *App) loadMoreResults() {
	if !a.results.hasMore() {
		return
	}
	a.results.loading = true
	a.fetchResults(a.results.query,
		ldapx.PageRequest{Size: a.profile.Limit(), Cookie: a.results.cookie}, true)
}

func (a *App) fetchResults(q ldapx.Query, req ldapx.PageRequest, appendPage bool) {
	if a.dir == nil {
		return
	}
	a.task(groupNone, fmt.Sprintf("searching %s…", q.Title()), func(ctx context.Context) (func(), error) {
		page, err := a.dir.Search(ctx, q, req)
		if err != nil {
			// A rejected filter is the common case and the user has to see it
			// in full, so it gets a dialog as well as the status line.
			failed := err
			return func() {
				a.results.loading = false
				a.showError(" Search failed ", failed)
			}, err
		}
		return func() {
			a.results.show(q, page, appendPage)
			a.left.SwitchToPage("results")
			a.SetFocus(a.results)
			a.refreshHints()
			switch {
			case len(a.results.entries) == 0:
				a.status.warn("%s matched nothing under %s", q.Title(), q.BaseDN)
			case page.Truncated:
				a.status.warn("%d matches shown; this server has no paged results, so raise the profile's child limit to see more",
					len(a.results.entries))
			case page.More():
				a.status.info("%d matches so far, more available", len(a.results.entries))
			default:
				a.status.ok("%d matches", len(a.results.entries))
			}
		}, nil
	})
}

// historyLimit caps the trail. Deep enough to retrace an afternoon of chasing
// group memberships, shallow enough not to grow without bound.
const historyLimit = 100

// recordJump notes where the user is leaving from before a jump takes them
// somewhere else, and drops any forward trail — the same thing a browser does
// when you follow a link after going back.
func (a *App) recordJump(to string) {
	from := a.currentDN()
	if from == "" || ldapx.EqualDN(from, to) {
		return
	}
	a.back = append(a.back, from)
	if len(a.back) > historyLimit {
		a.back = a.back[len(a.back)-historyLimit:]
	}
	a.forward = nil
}

// currentDN is where the user is now: the tree cursor, or the entry the object
// pane is showing when the tree cannot reach it.
func (a *App) currentDN() string {
	if dn := a.tree.currentDN(); dn != "" {
		return dn
	}
	if e := a.object.entry; e != nil {
		return e.DN
	}
	return ""
}

// goBack returns to the previously visited entry.
func (a *App) goBack() {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	if len(a.back) == 0 {
		a.status.info("nothing to go back to")
		return
	}
	dn := a.back[len(a.back)-1]
	a.back = a.back[:len(a.back)-1]
	if here := a.currentDN(); here != "" {
		a.forward = append(a.forward, here)
	}
	a.navigateTo(dn, false)
}

// goForward undoes a goBack.
func (a *App) goForward() {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	if len(a.forward) == 0 {
		a.status.info("nothing to go forward to")
		return
	}
	dn := a.forward[len(a.forward)-1]
	a.forward = a.forward[:len(a.forward)-1]
	if here := a.currentDN(); here != "" {
		a.back = append(a.back, here)
	}
	a.navigateTo(dn, false)
}

// jumpFromResults takes the chosen hit back into the tree, which is where the
// entry's surroundings are.
func (a *App) jumpFromResults(dn string) {
	a.closeResults()
	a.jumpToDN(dn)
}

func (a *App) closeResults() {
	a.left.SwitchToPage("tree")
	a.SetFocus(a.tree)
	a.refreshHints()
	// Put the object pane back on whatever the tree is pointing at, rather than
	// leaving it showing a result that is no longer selected anywhere.
	a.loadEntry(a.tree.currentDN())
}

// promptJumpToDN asks for a DN and goes there, for the case where you have one
// on the clipboard rather than on screen.
func (a *App) promptJumpToDN() {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	name := ""
	name = a.openModal(promptBox(" Go to DN ", "DN", "",
		"Expands whatever is closed on the way.",
		func(dn string) {
			a.closeModal(name)
			if dn = strings.TrimSpace(dn); dn != "" {
				a.jumpToDN(dn)
			}
		},
		func() { a.closeModal(name) },
	))
}

// ----------------------------------------------------------------- bookmarks

// toggleBookmark saves or unsaves the selected DN on the current profile.
func (a *App) toggleBookmark() {
	dn := a.tree.currentDN()
	if a.dir == nil || dn == "" {
		return
	}
	p := a.profile
	added := p.AddBookmark(dn)
	if !added {
		p.RemoveBookmark(dn)
	}
	if err := a.opts.Profiles.Put(p); err != nil {
		a.showError("Save bookmark", err)
		return
	}
	a.profile = p
	if added {
		a.status.ok("bookmarked %s", dn)
		return
	}
	a.status.info("removed the bookmark for %s", dn)
}

func (a *App) openBookmarks() {
	if a.dir == nil {
		a.status.warn("not connected")
		return
	}
	name := ""
	name = a.openModal(bookmarkList(a.profile.Display(), a.profile.Bookmarks,
		func(dn string) {
			a.closeModal(name)
			a.jumpToDN(dn)
		},
		func(dn string) {
			p := a.profile
			if !p.RemoveBookmark(dn) {
				return
			}
			if err := a.opts.Profiles.Put(p); err != nil {
				a.showError("Save bookmark", err)
				return
			}
			a.profile = p
			a.closeModal(name)
			a.openBookmarks()
			a.status.info("removed the bookmark for %s", dn)
		},
		func() { a.closeModal(name) },
	))
}

// --------------------------------------------------------------------- LDIF

// copyEntryAsLDIF puts the entry under the cursor on the clipboard as LDIF.
func (a *App) copyEntryAsLDIF() {
	if e := a.object.entry; e != nil {
		a.copyToClipboard("entry as LDIF", ldif.String(e))
		return
	}
	a.status.warn("no entry loaded")
}

// exportSubtree writes the selected entry and everything beneath it to a file.
//
// It walks the subtree itself rather than asking for one giant result, so a
// server without paging still exports fully, and so progress can be reported.
func (a *App) exportSubtree() {
	dn := a.tree.currentDN()
	if a.dir == nil || dn == "" {
		a.status.warn("select an entry to export")
		return
	}

	name := ""
	name = a.openModal(promptBox(" Export subtree to LDIF ", "File", defaultExportPath(dn),
		fmt.Sprintf("Writes %s and everything beneath it. An existing file is not overwritten.", dn),
		func(path string) {
			a.closeModal(name)
			a.runExport(dn, strings.TrimSpace(path))
		},
		func() { a.closeModal(name) },
	))
}

// defaultExportPath suggests a filename from the RDN, so the common case is one
// keypress.
func defaultExportPath(dn string) string {
	rdn := ldapx.RDN(dn)
	if i := strings.Index(rdn, "="); i >= 0 {
		rdn = rdn[i+1:]
	}
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, rdn)
	if safe == "" {
		safe = "export"
	}
	return safe + ".ldif"
}

func (a *App) runExport(dn, path string) {
	if path == "" {
		a.status.warn("no file name given")
		return
	}
	profile := a.profile
	limit := a.profile.Limit()

	fail := func(err error) (func(), error) {
		// A path that already exists or cannot be written is worth stopping on,
		// and the message is usually too long for the one-line status bar.
		return func() { a.showError(" Export failed ", err) }, err
	}

	a.task(groupNone, fmt.Sprintf("exporting %s…", dn), func(ctx context.Context) (func(), error) {
		entries, err := collectSubtree(ctx, a.dir, dn, limit)
		if err != nil {
			return fail(err)
		}

		// Exclusive create: an export must never quietly eat an existing file.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fail(fmt.Errorf("cannot write %s: %w", path, err))
		}
		defer f.Close()

		header := ldif.Comment("exported by PADL from %s\n%s\n%d entries",
			profile.URL(), dn, len(entries))
		if _, err := f.WriteString(header + "\n"); err != nil {
			return fail(fmt.Errorf("write %s: %w", path, err))
		}
		if err := ldif.WriteEntries(f, entries); err != nil {
			return fail(fmt.Errorf("write %s: %w", path, err))
		}

		n := len(entries)
		return func() { a.status.ok("wrote %d entries to %s", n, path) }, nil
	})
}

// collectSubtree reads an entry and everything beneath it, following pages.
//
// A subtree search would be one round trip, but it returns only the attributes
// the server feels like giving for each entry; walking level by level and
// reading each entry in full is what makes the export usable as input.
func collectSubtree(ctx context.Context, dir ldapx.Directory, root string, pageSize int) ([]ldapx.Entry, error) {
	var (
		out     []ldapx.Entry
		queue   = []string{root}
		visited = map[string]bool{}
	)
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dn := queue[0]
		queue = queue[1:]
		key := strings.ToLower(dn)
		if visited[key] {
			continue
		}
		visited[key] = true

		e, err := dir.Entry(ctx, dn, false)
		if err != nil {
			// A subtree can contain an entry the bind cannot read. Skipping it
			// is better than failing the whole export, but it must not be
			// silent — the count in the header is the honest record.
			continue
		}
		out = append(out, *e)

		req := ldapx.PageRequest{Size: pageSize}
		for {
			page, err := dir.Children(ctx, dn, req)
			if err != nil {
				return nil, err
			}
			for _, child := range page.Entries {
				queue = append(queue, child.DN)
			}
			if !page.More() {
				break
			}
			req = page.Next(pageSize)
		}
	}
	return out, nil
}
