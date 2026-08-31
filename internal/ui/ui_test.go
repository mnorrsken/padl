package ui

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ldapx"
)

// ---------------------------------------------------------------- fake server

// fakeDir is a directory served entirely from memory, so the UI tests never
// open a socket and never depend on a server being installed.
type fakeDir struct {
	mu sync.Mutex

	root     *ldapx.RootDSE
	children map[string][]ldapx.Entry
	entries  map[string]*ldapx.Entry

	// childErr, when set for a DN, fails that one expansion.
	childErr map[string]error
	// block, when set, holds Children until it is closed, for cancellation tests.
	block chan struct{}
	// entryHook, when set, runs at the start of every Entry call, so a test can
	// hold a read open across a disconnect.
	entryHook func()

	closed    bool
	lastOpAsk bool // whether the last Entry call asked for operational attributes
}

func attr(name string, values ...string) ldapx.Attribute {
	a := ldapx.Attribute{Name: name}
	for _, v := range values {
		a.Values = append(a.Values, []byte(v))
	}
	return a
}

func newEntry(dn string, attrs ...ldapx.Attribute) ldapx.Entry {
	return ldapx.Entry{DN: dn, Attributes: attrs, Subordinates: -1}
}

// sampleDir is a small tree: two OUs under a domain, with a user in one of them.
func sampleDir() *fakeDir {
	base := "dc=example,dc=com"
	people := "ou=People," + base
	groups := "ou=Groups," + base
	jdoe := "uid=jdoe," + people

	d := &fakeDir{
		children: map[string][]ldapx.Entry{},
		entries:  map[string]*ldapx.Entry{},
		childErr: map[string]error{},
	}
	d.root = ldapx.NewRootDSE(map[string][]string{
		"namingContexts": {base},
		"vendorName":     {"OpenLDAP Foundation"},
	})

	d.children[base] = []ldapx.Entry{
		newEntry(groups, attr("objectClass", "top", "organizationalUnit")),
		newEntry(people, attr("objectClass", "top", "organizationalUnit")),
	}
	d.children[people] = []ldapx.Entry{
		newEntry(jdoe, attr("objectClass", "top", "inetOrgPerson")),
	}
	d.children[groups] = nil
	d.children[jdoe] = nil

	d.entries[base] = ptr(newEntry(base, attr("objectClass", "top", "domain"), attr("dc", "example")))
	d.entries[people] = ptr(newEntry(people, attr("objectClass", "top", "organizationalUnit"), attr("ou", "People")))
	d.entries[groups] = ptr(newEntry(groups, attr("objectClass", "top", "organizationalUnit"), attr("ou", "Groups")))
	d.entries[jdoe] = ptr(newEntry(jdoe,
		attr("objectClass", "top", "inetOrgPerson"),
		attr("uid", "jdoe"),
		attr("cn", "John Doe"),
		attr("mail", "jdoe@example.com", "john.doe@example.com"),
	))
	return d
}

// withGroup adds a group under ou=Groups whose member values point at people,
// which is the case DN links exist for.
func withGroup(d *fakeDir) *fakeDir {
	base := "dc=example,dc=com"
	people := "ou=People," + base
	groups := "ou=Groups," + base
	jdoe := "uid=jdoe," + people
	asmith := "uid=asmith," + people
	engineers := "cn=engineers," + groups

	d.children[people] = append(d.children[people],
		newEntry(asmith, attr("objectClass", "top", "inetOrgPerson")))
	d.entries[asmith] = ptr(newEntry(asmith,
		attr("objectClass", "top", "inetOrgPerson"),
		attr("uid", "asmith"),
		attr("cn", "Alice Smith"),
		attr("memberOf", engineers),
	))
	d.entries[jdoe].Attributes = append(d.entries[jdoe].Attributes, attr("memberOf", engineers))

	d.children[groups] = []ldapx.Entry{newEntry(engineers, attr("objectClass", "top", "groupOfNames"))}
	d.children[engineers] = nil
	d.entries[engineers] = ptr(newEntry(engineers,
		attr("objectClass", "top", "groupOfNames"),
		attr("cn", "engineers"),
		attr("member", jdoe, asmith),
		// A value that is not a DN, and one that is a DN outside the tree.
		attr("description", "The engineering team"),
		attr("seeAlso", "cn=other,dc=elsewhere,dc=net"),
	))
	return d
}

func ptr(e ldapx.Entry) *ldapx.Entry { return &e }

func (d *fakeDir) RootDSE(context.Context) (*ldapx.RootDSE, error) { return d.root, nil }

func (d *fakeDir) Children(ctx context.Context, dn string, limit int) ([]ldapx.Entry, bool, error) {
	d.mu.Lock()
	block := d.block
	err := d.childErr[dn]
	kids := append([]ldapx.Entry(nil), d.children[dn]...)
	d.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
	if err != nil {
		return nil, false, err
	}
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	truncated := false
	if limit > 0 && len(kids) > limit {
		kids = kids[:limit]
		truncated = true
	}
	ldapx.SortEntries(kids)
	return kids, truncated, nil
}

func (d *fakeDir) Entry(ctx context.Context, dn string, operational bool) (*ldapx.Entry, error) {
	d.mu.Lock()
	hook := d.entryHook
	d.mu.Unlock()
	if hook != nil {
		hook()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastOpAsk = operational
	e, ok := d.entries[dn]
	if !ok {
		return nil, fmt.Errorf("no such entry: %s", dn)
	}
	out := *e
	if operational {
		out.Attributes = append(append([]ldapx.Attribute(nil), out.Attributes...),
			ldapx.Attribute{Name: "createTimestamp", Values: [][]byte{[]byte("20240115103000Z")}, Operational: true})
	}
	return &out, nil
}

func (d *fakeDir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func (d *fakeDir) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// ------------------------------------------------------------------ harness

type harness struct {
	t      *testing.T
	app    *App
	screen tcell.SimulationScreen
	dir    *fakeDir

	profiles *config.Store
	trust    *config.TrustStore

	done chan error
}

func testProfile() config.Profile {
	p := config.NewProfile()
	p.ID = "lab"
	p.Name = "Lab"
	p.Host = "ldap.example.test"
	p.Bind = config.BindAnonymous
	p.BindDN = ""
	p.PasswordRef = ""
	return p
}

// start boots the app on a simulated terminal with the given connector.
//
// seed, if given, runs against the fresh stores before the app is built — the
// way to test a second run that already has a pinned certificate on file.
func start(t *testing.T, p config.Profile, connect Connector, secrets *config.Secrets, seed ...func(*config.TrustStore)) *harness {
	t.Helper()
	dir := t.TempDir()
	profiles, err := config.LoadStore(filepath.Join(dir, "profiles.yaml"))
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	if err := profiles.Put(p); err != nil {
		t.Fatalf("put profile: %v", err)
	}
	trust, err := config.LoadTrustStore(filepath.Join(dir, "trust.yaml"))
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	if secrets == nil {
		secrets = &config.Secrets{}
	}
	for _, fn := range seed {
		fn(trust)
	}

	screen := tcell.NewSimulationScreen("UTF-8")

	h := &harness{t: t, screen: screen, profiles: profiles, trust: trust, done: make(chan error, 1)}
	h.app = New(Options{
		Profiles:       profiles,
		Trust:          trust,
		Secrets:        secrets,
		Screen:         screen,
		Connect:        connect,
		InitialProfile: p.ID,
	})

	// After New: SetScreen initialises the screen, which resets it to the
	// default 80x25. A wider one keeps long DNs from being clipped mid-test.
	screen.SetSize(160, 48)

	go func() { h.done <- h.app.Run() }()
	t.Cleanup(func() {
		h.app.Stop()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("app did not stop")
		}
	})
	return h
}

// text is everything currently on the simulated screen, one string per row.
//
// The read runs on the application's own goroutine: SimulationScreen.GetContents
// hands back the live cell buffer rather than a copy, so reading it from the
// test goroutine races every redraw. It is queued without a redraw of its own —
// key presses and task results already trigger those, and asking for one here
// would keep drawing from a goroutine that can outlive the test.
func (h *harness) text() string {
	out := make(chan string, 1)
	go h.app.QueueUpdate(func() { out <- h.render() })
	select {
	case s := <-out:
		return s
	case <-time.After(2 * time.Second):
		return "<screen read timed out>"
	}
}

// styleOf returns the style of the first cell of the first occurrence of want,
// so a test can assert what a row actually looks like rather than only what it
// says.
func (h *harness) styleOf(want string) (tcell.Style, bool) {
	type result struct {
		style tcell.Style
		ok    bool
	}
	out := make(chan result, 1)
	go h.app.QueueUpdate(func() {
		cells, w, height := h.screen.GetContents()
		for y := 0; y < height; y++ {
			var row strings.Builder
			for x := 0; x < w; x++ {
				c := cells[y*w+x]
				if len(c.Runes) == 0 {
					row.WriteByte(' ')
					continue
				}
				row.WriteRune(c.Runes[0])
			}
			if i := strings.Index(row.String(), want); i >= 0 {
				out <- result{cells[y*w+i].Style, true}
				return
			}
		}
		out <- result{}
	})
	select {
	case r := <-out:
		return r.style, r.ok
	case <-time.After(2 * time.Second):
		return tcell.StyleDefault, false
	}
}

func (h *harness) render() string {
	cells, w, height := h.screen.GetContents()
	var b strings.Builder
	for y := 0; y < height; y++ {
		for x := 0; x < w; x++ {
			c := cells[y*w+x]
			if len(c.Runes) == 0 {
				b.WriteByte(' ')
				continue
			}
			b.WriteRune(c.Runes[0])
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// waitFor polls the screen until every wanted string is on it.
func (h *harness) waitFor(want ...string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var screen string
	for time.Now().Before(deadline) {
		screen = h.text()
		missing := false
		for _, w := range want {
			if !strings.Contains(screen, w) {
				missing = true
				break
			}
		}
		if !missing {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %q\nscreen:\n%s", want, screen)
}

// waitUntil polls an arbitrary condition, for state that is not on screen.
func (h *harness) waitUntil(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s\nscreen:\n%s", what, h.text())
}

// fingerprintLines is what the prompt actually renders: a SHA-256 is too long
// for an 80-column dialog, so it is shown split across two lines.
func fingerprintLines(fp string) []string {
	return splitFingerprint(fp)
}

func (h *harness) key(k tcell.Key) {
	h.screen.InjectKey(k, 0, tcell.ModNone)
}

func (h *harness) rune(r rune) {
	h.screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
}

func (h *harness) typeString(s string) {
	for _, r := range s {
		h.rune(r)
		time.Sleep(2 * time.Millisecond)
	}
}

// okConnector always succeeds, handing back the same fake directory.
func okConnector(d *fakeDir) Connector {
	return func(context.Context, config.Profile, *config.Pin, string) (ldapx.Directory, error) {
		return d, nil
	}
}

// --------------------------------------------------------------------- tests

func TestBrowseTreeAndReadEntry(t *testing.T) {
	d := sampleDir()
	h := start(t, testProfile(), okConnector(d), nil)

	// The first naming context opens by itself, so the tree is never an
	// unexplained single row.
	h.waitFor("dc=example,dc=com", "ou=Groups", "ou=People")

	// The highlighted row loads into the object pane.
	h.waitFor("dn: dc=example,dc=com", "objectClass", "domain")

	// Walk to ou=People and expand it.
	h.key(tcell.KeyDown) // ou=Groups
	h.key(tcell.KeyDown) // ou=People
	h.waitFor("dn: ou=People,dc=example,dc=com")

	h.key(tcell.KeyRight)
	h.waitFor("uid=jdoe")

	h.key(tcell.KeyDown)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com", "John Doe", "jdoe@example.com")

	// Both values of a multi-valued attribute are listed.
	h.waitFor("john.doe@example.com")
}

// tview reads square brackets as style tags, so an unescaped label loses its
// icon — and, worse, loses part of any RDN that legally contains brackets.
func TestTreeLabelsSurviveTviewTagParsing(t *testing.T) {
	d := sampleDir()
	base := "dc=example,dc=com"
	odd := `cn=Rack [A1],` + base
	d.children[base] = append(d.children[base], newEntry(odd, attr("objectClass", "device")))
	d.entries[odd] = ptr(newEntry(odd, attr("objectClass", "device")))

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	screen := h.text()
	// The person icon is "[u]", which a tag parser would swallow whole.
	if !strings.Contains(screen, "[u] uid=") && !strings.Contains(screen, "[+] ou=People") {
		t.Errorf("tree icons were eaten by the tag parser:\n%s", screen)
	}
	if !strings.Contains(screen, "cn=Rack [A1]") {
		t.Errorf("an RDN containing brackets was mangled:\n%s", screen)
	}
}

func TestContainersSortAboveLeaves(t *testing.T) {
	d := sampleDir()
	base := "dc=example,dc=com"
	d.children[base] = append(d.children[base],
		newEntry("uid=aaron,"+base, attr("objectClass", "top", "inetOrgPerson")))
	d.entries["uid=aaron,"+base] = ptr(newEntry("uid=aaron,"+base, attr("objectClass", "inetOrgPerson")))

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=Groups", "ou=People", "uid=aaron")

	screen := h.text()
	groups := strings.Index(screen, "ou=Groups")
	people := strings.Index(screen, "ou=People")
	aaron := strings.Index(screen, "uid=aaron")
	if !(groups < people && people < aaron) {
		t.Errorf("containers should sort above leaves; got Groups=%d People=%d aaron=%d\n%s",
			groups, people, aaron, screen)
	}
}

func TestOperationalAttributesToggle(t *testing.T) {
	d := sampleDir()
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("dn: dc=example,dc=com")

	if strings.Contains(h.text(), "createTimestamp") {
		t.Fatal("operational attributes should start hidden")
	}

	// The object pane owns 'o', so focus has to move there first.
	h.key(tcell.KeyTab)
	h.rune('o')
	h.waitFor("createTimestamp")

	h.rune('o')
	h.waitUntil("operational attributes to disappear", func() bool {
		return !strings.Contains(h.text(), "createTimestamp")
	})
}

// An empty container simply becomes a leaf. Hanging an "(empty)" row under
// every user and group would be noise on every screen.
func TestEmptyContainerBecomesALeafWithoutAPlaceholder(t *testing.T) {
	d := sampleDir()
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=Groups")

	h.key(tcell.KeyDown) // ou=Groups, which has no children
	h.key(tcell.KeyRight)
	h.waitFor("dn: ou=Groups,dc=example,dc=com")

	h.waitUntil("the expand to settle", func() bool {
		return !strings.Contains(h.text(), "loading…")
	})
	screen := h.text()
	if strings.Contains(screen, "(empty)") {
		t.Errorf("an empty container should not gain a placeholder row:\n%s", screen)
	}
	// Nothing was added under it, and the tree is otherwise intact.
	if !strings.Contains(screen, "ou=People") {
		t.Errorf("the rest of the tree should be unchanged:\n%s", screen)
	}
}

// A server that says an entry has no children is taken at its word: expanding
// it must not cost a round trip, and must not add anything to the screen.
func TestKnownLeafIsNeverQueried(t *testing.T) {
	d := sampleDir()
	jdoe := "uid=jdoe,ou=People,dc=example,dc=com"
	no := false
	for i := range d.children["ou=People,dc=example,dc=com"] {
		d.children["ou=People,dc=example,dc=com"][i].HasSubordinates = &no
	}
	// Any attempt to list the user's children is a failure of the test's premise.
	d.childErr[jdoe] = errors.New("the tree should not have asked for these")

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("uid=jdoe")

	h.key(tcell.KeyDown)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")
	h.key(tcell.KeyRight)
	h.key(tcell.KeyRight)

	h.waitUntil("the screen to settle", func() bool {
		return !strings.Contains(h.text(), "loading…")
	})
	if strings.Contains(h.text(), "should not have asked") {
		t.Errorf("a known leaf was expanded anyway:\n%s", h.text())
	}
}

// tview derives the highlight from a node's colour, so a row left at the
// terminal default came out dark-on-dark and effectively invisible.
func TestSelectedTreeRowIsLegible(t *testing.T) {
	d := sampleDir()
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	// Move onto a non-container row, which is where the highlight broke.
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("uid=jdoe")
	h.key(tcell.KeyDown)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")

	// The tree row, not the object pane's heading: "[u] " only appears in the
	// tree.
	style, ok := h.styleOf("[u] uid=jdoe")
	if !ok {
		t.Fatalf("could not find the selected row:\n%s", h.text())
	}
	fg, bg, _ := style.Decompose()
	if fg == bg {
		t.Errorf("selected row is %v on %v — invisible", fg, bg)
	}
	if bg == tcell.ColorDefault {
		t.Errorf("selected row background is the terminal default, so it does not read as selected")
	}
}

func TestChildLoadFailureIsReportedAndRetryable(t *testing.T) {
	d := sampleDir()
	people := "ou=People,dc=example,dc=com"
	d.childErr[people] = errors.New("size limit exceeded")

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.key(tcell.KeyRight)
	h.waitFor("size limit exceeded")

	// The node reverts to unloaded, so a second try actually re-queries.
	d.mu.Lock()
	delete(d.childErr, people)
	d.mu.Unlock()
	h.key(tcell.KeyRight)
	h.waitFor("uid=jdoe")
}

// The whole point of the async plumbing is that a slow server does not freeze
// the terminal: Esc has to still be handled while a search is outstanding.
func TestEscapeCancelsInFlightSearch(t *testing.T) {
	d := sampleDir()
	d.block = make(chan struct{})

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("loading…")

	h.key(tcell.KeyEscape)
	h.waitFor("cancelled")

	close(d.block)
}

func TestTruncatedContainerIsFlagged(t *testing.T) {
	d := sampleDir()
	base := "dc=example,dc=com"
	for i := 0; i < 10; i++ {
		dn := fmt.Sprintf("uid=user%02d,%s", i, base)
		d.children[base] = append(d.children[base], newEntry(dn, attr("objectClass", "inetOrgPerson")))
		d.entries[dn] = ptr(newEntry(dn, attr("objectClass", "inetOrgPerson")))
	}

	p := testProfile()
	p.PageSize = 3
	h := start(t, p, okConnector(d), nil)

	h.waitFor("more than 3 entries")
}

// Opening a binary value and escaping back must return the keyboard to the
// object pane it was opened from, not dump the user back in the tree.
func TestValueInspectorOpensAndReturnsFocusToTheObjectPane(t *testing.T) {
	d := sampleDir()
	jdoe := "uid=jdoe,ou=People,dc=example,dc=com"
	guid := []byte{
		0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	d.entries[jdoe].Attributes = append(d.entries[jdoe].Attributes,
		ldapx.Attribute{Name: "objectGUID", Values: [][]byte{guid}})

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("uid=jdoe")
	h.key(tcell.KeyDown)
	h.waitFor("12345678-1234-5678-1234-56789abcdef0", "(enter to inspect)")

	// Into the object pane, then walk down until Enter opens the objectGUID
	// row. Enter inspects any value, so a wrong row opens the wrong popup and
	// is simply escaped.
	h.key(tcell.KeyTab)
	opened := false
	for i := 0; i < 20 && !opened; i++ {
		h.key(tcell.KeyEnter)
		h.waitUntil("a value inspector to open", func() bool {
			return strings.Contains(h.text(), "esc to close")
		})
		if strings.Contains(h.text(), "objectGUID — 16 bytes") {
			opened = true
			break
		}
		h.key(tcell.KeyEscape)
		h.waitUntil("the inspector to close", func() bool {
			return !strings.Contains(h.text(), "esc to close")
		})
		h.key(tcell.KeyDown)
	}
	if !opened {
		t.Fatalf("never reached the objectGUID row:\n%s", h.text())
	}
	// The inspector shows the bytes, which the one-line table cell cannot.
	h.waitFor("12 34 56 78 9a bc de f0")

	h.key(tcell.KeyEscape)
	h.waitUntil("the inspector to close", func() bool {
		return !strings.Contains(h.text(), "16 bytes")
	})

	// Focus is back on the object pane: 'o' is its key, and it must act.
	h.rune('o')
	h.waitFor("createTimestamp")
}

func TestDisconnectClosesTheConnection(t *testing.T) {
	d := sampleDir()
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("dc=example,dc=com")

	h.rune('c')
	h.waitFor("disconnected")
	h.waitUntil("the directory to be closed", d.isClosed)
}

// A read already on its way back when the user disconnects must not draw itself
// onto the disconnected screen.
func TestDisconnectDiscardsInFlightWork(t *testing.T) {
	d := sampleDir()
	release := make(chan struct{})
	d.entryHook = func() { <-release }

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	// Start a read that will not answer until released, then disconnect.
	h.key(tcell.KeyDown)
	h.rune('c')
	h.waitFor("disconnected")
	close(release)

	h.waitUntil("the directory to be closed", d.isClosed)
	// Give the abandoned read every chance to land on the wrong screen.
	if h.rowHighlighted("organizationalUnit", 300*time.Millisecond) {
		t.Errorf("a read from the closed connection was drawn:\n%s", h.text())
	}
	if strings.Contains(h.text(), "dn: ou=Groups") {
		t.Errorf("the object pane was repopulated after disconnecting:\n%s", h.text())
	}
}

func TestHelpOverlay(t *testing.T) {
	d := sampleDir()
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("dc=example,dc=com")

	h.rune('?')
	h.waitFor("Keys (esc to close)", "operational attributes")

	h.key(tcell.KeyEscape)
	h.waitUntil("the help overlay to close", func() bool {
		return !strings.Contains(h.text(), "Keys (esc to close)")
	})
}

// ------------------------------------------------------- certificate prompt

func fakeCert(cn string, raw string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
		Raw:          []byte(raw),
	}
}

func TestCertPromptPinsAndRetries(t *testing.T) {
	d := sampleDir()
	cert := fakeCert("ldap.example.test", "der-one")

	var mu sync.Mutex
	var calls []*config.Pin

	connect := func(_ context.Context, p config.Profile, pin *config.Pin, _ string) (ldapx.Directory, error) {
		mu.Lock()
		calls = append(calls, pin)
		n := len(calls)
		mu.Unlock()
		if n == 1 {
			// First attempt: nothing pinned, certificate does not verify.
			return nil, ldapx.NewCertTrustError(ldapx.TrustUntrusted, p.Host, cert, nil,
				errors.New("x509: certificate signed by unknown authority"))
		}
		return d, nil
	}

	h := start(t, testProfile(), connect, nil)

	h.waitFor(append([]string{"Untrusted certificate", "CN=ldap.example.test"},
		fingerprintLines(config.Fingerprint(cert))...)...)
	// Cancel is focused first, so a reflexive Enter declines. Tab over to accept.
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)

	h.waitFor("dc=example,dc=com", "ou=People")

	pin, ok := h.trust.Get("lab")
	if !ok {
		t.Fatal("accepting the prompt should write a pin")
	}
	if pin.Fingerprint != config.Fingerprint(cert) {
		t.Errorf("pinned %q, want %q", pin.Fingerprint, config.Fingerprint(cert))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("connect called %d times, want 2 (the retry after pinning)", len(calls))
	}
	if calls[0] != nil {
		t.Error("the first attempt should carry no pin")
	}
	if calls[1] == nil || calls[1].Fingerprint != config.Fingerprint(cert) {
		t.Errorf("the retry should carry the newly written pin, got %+v", calls[1])
	}
}

func TestCertPromptRejectionLeavesNoPin(t *testing.T) {
	cert := fakeCert("ldap.example.test", "der-one")
	var calls int
	var mu sync.Mutex

	connect := func(_ context.Context, p config.Profile, _ *config.Pin, _ string) (ldapx.Directory, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, ldapx.NewCertTrustError(ldapx.TrustUntrusted, p.Host, cert, nil,
			errors.New("x509: certificate signed by unknown authority"))
	}

	h := start(t, testProfile(), connect, nil)
	h.waitFor("Untrusted certificate")

	h.key(tcell.KeyEnter) // Cancel has focus
	h.waitFor("certificate rejected")

	if _, ok := h.trust.Get("lab"); ok {
		t.Error("rejecting the prompt must not pin anything")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("connect called %d times, want 1 — a rejection should not retry", calls)
	}
}

// A changed certificate is the case that matters, so it gets its own wording
// and does not read like an ordinary first connect.
func TestChangedCertPromptIsLouder(t *testing.T) {
	old := fakeCert("ldap.example.test", "der-old")
	fresh := fakeCert("ldap.example.test", "der-new")
	oldPin := config.PinFor(old)

	connect := func(_ context.Context, p config.Profile, _ *config.Pin, _ string) (ldapx.Directory, error) {
		return nil, ldapx.NewCertTrustError(ldapx.TrustChanged, p.Host, fresh, &oldPin,
			errors.New("x509: certificate signed by unknown authority"))
	}

	h := start(t, testProfile(), connect, nil)
	h.waitFor("CERTIFICATE CHANGED", "has changed since you trusted it", "Replace pin")
	// Both fingerprints are shown so the operator can see what changed.
	h.waitFor(fingerprintLines(config.Fingerprint(fresh))...)
	h.waitFor(fingerprintLines(oldPin.Fingerprint)...)
}

// ---------------------------------------------------------- password prompt

func TestPasswordPromptOnEmptyKeychain(t *testing.T) {
	d := sampleDir()
	var mu sync.Mutex
	var gotPassword string

	connect := func(_ context.Context, _ config.Profile, _ *config.Pin, password string) (ldapx.Directory, error) {
		mu.Lock()
		gotPassword = password
		mu.Unlock()
		return d, nil
	}

	p := testProfile()
	p.Bind = config.BindSimple
	p.BindDN = "cn=admin,dc=example,dc=com"
	p.PasswordRef = config.PasswordPrompt

	h := start(t, p, connect, &config.Secrets{})
	h.waitFor("Bind to Lab", "cn=admin,dc=example,dc=com")

	h.typeString("hunter2")
	h.key(tcell.KeyTab)   // off the password field, onto Connect
	h.key(tcell.KeyEnter) // press it

	h.waitFor("dc=example,dc=com", "ou=People")

	mu.Lock()
	defer mu.Unlock()
	if gotPassword != "hunter2" {
		t.Errorf("connected with password %q, want the typed one", gotPassword)
	}
}

func TestPasswordPromptCancel(t *testing.T) {
	var calls int
	var mu sync.Mutex
	connect := func(context.Context, config.Profile, *config.Pin, string) (ldapx.Directory, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return sampleDir(), nil
	}

	p := testProfile()
	p.Bind = config.BindSimple
	p.BindDN = "cn=admin,dc=example,dc=com"
	p.PasswordRef = config.PasswordPrompt

	h := start(t, p, connect, &config.Secrets{})
	h.waitFor("Bind to Lab")

	h.key(tcell.KeyTab) // move off the password field onto Connect
	h.key(tcell.KeyTab) // onto Cancel
	h.key(tcell.KeyEnter)
	h.waitFor("connect cancelled")

	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Errorf("connect called %d times after cancelling, want 0", calls)
	}
}

// ------------------------------------------------------------------ profiles

func TestConnectFailureIsShownNotSwallowed(t *testing.T) {
	connect := func(context.Context, config.Profile, *config.Pin, string) (ldapx.Directory, error) {
		return nil, errors.New("dial tcp: connection refused")
	}
	h := start(t, testProfile(), connect, nil)
	h.waitFor("connection refused")
}

func TestNoNamingContextsPointsAtTheBaseDN(t *testing.T) {
	d := sampleDir()
	d.root = ldapx.NewRootDSE(nil) // an eDirectory-style empty root DSE

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("no naming contexts", "set a base DN")
}

func TestProfileBaseDNOverridesEmptyRootDSE(t *testing.T) {
	d := sampleDir()
	d.root = ldapx.NewRootDSE(nil)

	p := testProfile()
	p.BaseDN = "dc=example,dc=com"

	h := start(t, p, okConnector(d), nil)
	h.waitFor("dc=example,dc=com", "ou=People")
}

// ------------------------------------------------------------- DN links

// selectValueRow walks the object pane down until want is the highlighted row.
//
// Each step waits for the keypress to actually land before deciding to press
// again: injected keys and queued screen reads travel on different channels, so
// reading eagerly sees the previous frame and walks straight past the target.
func (h *harness) selectValueRow(want string) {
	h.t.Helper()
	for i := 0; i < 60; i++ {
		if h.rowHighlighted(want, 200*time.Millisecond) {
			return
		}
		h.key(tcell.KeyDown)
	}
	h.t.Fatalf("never highlighted %q:\n%s", want, h.text())
}

// rowHighlighted reports whether want is the selected row, waiting up to within
// for it to become so.
func (h *harness) rowHighlighted(want string, within time.Duration) bool {
	h.t.Helper()
	deadline := time.Now().Add(within)
	for {
		if style, ok := h.styleOf(want); ok {
			if _, bg, _ := style.Decompose(); bg == colorSelected {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestFollowDNJumpsToTheEntryInTheTree(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=Groups")

	// Open the group and read its members.
	h.key(tcell.KeyDown) // ou=Groups
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com", "(enter to follow)")

	// A member is a link; the free-text description is not.
	screen := h.text()
	if !strings.Contains(screen, "uid=jdoe,ou=People,dc=example,dc=com  (enter to follow)") {
		t.Errorf("member should render as a link:\n%s", screen)
	}
	if strings.Contains(screen, "The engineering team  (enter to follow)") {
		t.Errorf("free text must not become a link:\n%s", screen)
	}
	// A DN outside every naming context is not navigable, so not a link.
	if strings.Contains(screen, "cn=other,dc=elsewhere,dc=net  (enter to follow)") {
		t.Errorf("a DN outside the tree must not become a link:\n%s", screen)
	}

	h.key(tcell.KeyTab)
	h.selectValueRow("uid=jdoe,ou=People,dc=example,dc=com  (enter to follow)")
	h.key(tcell.KeyEnter)

	// ou=People was never opened; the jump has to expand it on the way.
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com", "John Doe")
	h.waitFor("[u] uid=jdoe")

	// The cursor really moved, and the tree has focus: 'r' is a tree key.
	style, ok := h.styleOf("[u] uid=jdoe")
	if !ok {
		t.Fatalf("uid=jdoe is not in the tree:\n%s", h.text())
	}
	if _, bg, _ := style.Decompose(); bg != tcell.ColorBlue {
		t.Errorf("the jump target should be the selected row, got background %v", bg)
	}
}

// The link works in both directions: memberOf goes back to the group.
func TestFollowDNGoesBackUpToTheGroup(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.key(tcell.KeyRight)
	h.waitFor("uid=asmith")
	h.key(tcell.KeyDown)
	h.waitFor("dn: uid=asmith,ou=People,dc=example,dc=com", "Alice Smith")

	h.key(tcell.KeyTab)
	h.selectValueRow("cn=engineers,ou=Groups,dc=example,dc=com  (enter to follow)")
	h.key(tcell.KeyEnter)

	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com", "groupOfNames")
	h.waitFor("[g] cn=engineers")
}

// A DN under a naming context that is hidden should say which key reveals it,
// rather than failing silently.
func TestFollowDNOutsideTheShownTreeExplainsItself(t *testing.T) {
	d := withGroup(sampleDir())
	engineers := "cn=engineers,ou=Groups,dc=example,dc=com"
	d.entries[engineers].Attributes = append(d.entries[engineers].Attributes,
		attr("owner", "cn=admin,dc=example,dc=com"))
	// Make the owner unreachable by pointing it at a base that is not shown.
	d.entries[engineers].Attributes[len(d.entries[engineers].Attributes)-1] =
		attr("owner", "cn=admin,dc=hidden,dc=com")

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=Groups")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	// It is not offered as a link at all, because it cannot be reached.
	if strings.Contains(h.text(), "cn=admin,dc=hidden,dc=com  (enter to follow)") {
		t.Errorf("an unreachable DN must not be offered as a link:\n%s", h.text())
	}
}

// A member that no longer exists must say so plainly rather than leaving the
// cursor somewhere arbitrary.
func TestFollowDNReportsAMissingEntry(t *testing.T) {
	d := withGroup(sampleDir())
	engineers := "cn=engineers,ou=Groups,dc=example,dc=com"
	ghost := "uid=ghost,ou=People,dc=example,dc=com"
	d.entries[engineers].Attributes = append(d.entries[engineers].Attributes, attr("member", ghost))

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=Groups")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	h.key(tcell.KeyTab)
	h.selectValueRow(ghost + "  (enter to follow)")
	h.key(tcell.KeyEnter)

	h.waitFor("uid=ghost,ou=People,dc=example,dc=com does not exist under ou=People,dc=example,dc=com")
}

// When the target's parent was truncated the entry may simply not have been
// loaded, which is a different problem with a different fix.
func TestFollowDNReportsTruncationRatherThanAbsence(t *testing.T) {
	d := withGroup(sampleDir())
	people := "ou=People,dc=example,dc=com"
	engineers := "cn=engineers,ou=Groups,dc=example,dc=com"
	for i := 0; i < 10; i++ {
		dn := fmt.Sprintf("uid=user%02d,%s", i, people)
		d.children[people] = append(d.children[people], newEntry(dn, attr("objectClass", "inetOrgPerson")))
		d.entries[dn] = ptr(newEntry(dn, attr("objectClass", "inetOrgPerson")))
	}
	target := fmt.Sprintf("uid=user09,%s", people)
	d.entries[engineers].Attributes = append(d.entries[engineers].Attributes, attr("member", target))

	p := testProfile()
	p.PageSize = 2
	h := start(t, p, okConnector(d), nil)
	h.waitFor("ou=Groups")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	h.key(tcell.KeyTab)
	h.selectValueRow(target + "  (enter to follow)")
	h.key(tcell.KeyEnter)

	h.waitFor("was not among the first", "raise the profile's child limit")
}
