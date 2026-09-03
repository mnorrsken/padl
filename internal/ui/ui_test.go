package ui

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
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
	// noPaging makes the fake behave like a server without RFC 2696: it
	// truncates instead of handing back a cookie.
	noPaging bool
	// searchErr, when set, fails every Search — a bad filter, typically.
	searchErr error

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

// withManyUsers adds n users under ou=People so paging has something to page.
func withManyUsers(d *fakeDir, n int) *fakeDir {
	people := "ou=People,dc=example,dc=com"
	for i := 0; i < n; i++ {
		dn := fmt.Sprintf("uid=user%02d,%s", i, people)
		d.children[people] = append(d.children[people], newEntry(dn, attr("objectClass", "inetOrgPerson")))
		d.entries[dn] = ptr(newEntry(dn, attr("objectClass", "inetOrgPerson"), attr("uid", fmt.Sprintf("user%02d", i))))
	}
	return d
}

func (d *fakeDir) RootDSE(context.Context) (*ldapx.RootDSE, error) { return d.root, nil }

// Children pages the way a real server does: a cookie carries the offset, and
// an empty cookie back means that was the last page. paging=false makes it
// behave like a server with no RFC 2696 support, which truncates instead.
func (d *fakeDir) Children(ctx context.Context, dn string, req ldapx.PageRequest) (*ldapx.Page, error) {
	d.mu.Lock()
	block := d.block
	err := d.childErr[dn]
	kids := append([]ldapx.Entry(nil), d.children[dn]...)
	paging := !d.noPaging
	d.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	ldapx.SortEntries(kids)
	return pageOf(kids, req, paging)
}

// Search filters the whole fake directory. The filter is not parsed: tests pass
// a substring to match against the DN, which is enough to drive the UI without
// reimplementing RFC 4515 in a test double.
func (d *fakeDir) Search(ctx context.Context, q ldapx.Query, req ldapx.PageRequest) (*ldapx.Page, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.searchErr != nil {
		return nil, d.searchErr
	}

	var hits []ldapx.Entry
	for dn, e := range d.entries {
		if ldapx.DepthUnder(dn, q.BaseDN) < 0 {
			continue
		}
		switch q.Scope {
		case ldapx.ScopeBase:
			if !ldapx.EqualDN(dn, q.BaseDN) {
				continue
			}
		case ldapx.ScopeOneLevel:
			if ldapx.DepthUnder(dn, q.BaseDN) != 1 {
				continue
			}
		}
		// Every distinct term in the filter has to appear, mirroring the AND a
		// quick search builds.
		matched := true
		for _, term := range quickTerms(q.Filter) {
			if !strings.Contains(strings.ToLower(dn), strings.ToLower(term)) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		hits = append(hits, *e)
	}
	ldapx.SortEntries(hits)
	return pageOf(hits, req, !d.noPaging)
}

// pageOf slices one page out of a result set, honouring the cookie as an
// offset. Shared by Children and Search so both page the same way.
func pageOf(hits []ldapx.Entry, req ldapx.PageRequest, paging bool) (*ldapx.Page, error) {
	size := req.Size
	if size <= 0 {
		size = len(hits)
	}

	if !paging {
		page := &ldapx.Page{Entries: hits}
		if len(hits) > size {
			page.Entries = hits[:size]
			page.Truncated = true
		}
		return page, nil
	}

	offset := 0
	if len(req.Cookie) > 0 {
		n, err := strconv.Atoi(string(req.Cookie))
		if err != nil {
			return nil, fmt.Errorf("bad cookie %q", req.Cookie)
		}
		offset = n
	}
	if offset > len(hits) {
		offset = len(hits)
	}
	end := offset + size
	if end > len(hits) {
		end = len(hits)
	}

	page := &ldapx.Page{Entries: hits[offset:end]}
	if end < len(hits) {
		page.Cookie = []byte(strconv.Itoa(end))
	}
	return page, nil
}

// searchNeedle reduces a filter to the values it is looking for, so the fake
// can match without implementing RFC 4515. A quick search produces one clause
// per term, and every term has to match — which is enough to tell a working
// quick search from a broken one.
func searchNeedle(filter string) string {
	if vals := filterValues(filter); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// filterValues pulls every "=value" out of a filter, stripped of wildcards.
func filterValues(filter string) []string {
	var out []string
	for _, part := range strings.Split(filter, "(") {
		i := strings.Index(part, "=")
		if i < 0 {
			continue
		}
		// The tail of a filter carries closing parens for every enclosing
		// group, so trim any run of them along with the wildcards. A value
		// containing a real paren arrives escaped as \29, so nothing is lost.
		v := strings.Trim(part[i+1:], "*)")
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// quickTerms returns the distinct terms a quick-search filter is ANDing, which
// is what a match has to satisfy all of.
func quickTerms(filter string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range filterValues(filter) {
		k := strings.ToLower(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
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

// loadAllPages walks to the "load more" row and presses it until every page is
// in, waiting for each one to land before pressing again.
//
// Stepping blindly would either press enter on an ordinary row — which does
// something quite different — or fire a second load before the first returned.
func (h *harness) loadAllPages(rowMarker string) {
	h.t.Helper()
	const moreRow = "so far, enter for more"
	for page := 0; page < 12; page++ {
		if !strings.Contains(h.text(), moreRow) {
			return
		}
		found := false
		for i := 0; i < 40; i++ {
			if h.rowHighlighted(moreRow, 150*time.Millisecond) {
				found = true
				break
			}
			h.key(tcell.KeyDown)
		}
		if !found {
			h.t.Fatalf("could not reach the load-more row:\n%s", h.text())
		}
		before := strings.Count(h.text(), rowMarker)
		h.key(tcell.KeyEnter)
		h.waitUntil("the next page to arrive", func() bool {
			return strings.Count(h.text(), rowMarker) > before ||
				!strings.Contains(h.text(), moreRow)
		})
	}
	h.t.Fatalf("paging never finished:\n%s", h.text())
}

// isLink reports whether a value is rendered as a followable DN, which is shown
// by underlining rather than by any text label.
func (h *harness) isLink(value string) bool {
	h.t.Helper()
	style, ok := h.styleOf(value)
	if !ok {
		return false
	}
	_, _, attrs := style.Decompose()
	return attrs&tcell.AttrUnderline != 0
}

// waitConnected waits until a connection is actually up.
//
// Waiting for a piece of tree text is not enough: the same text can still be on
// screen from before a disconnect, so a test can race ahead and act while the
// app is between connections. The header is unambiguous.
func (h *harness) waitConnected() {
	h.t.Helper()
	h.waitUntil("the connection to be up", func() bool {
		return !strings.Contains(h.text(), "not connected")
	})
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

// Nothing in LDAP stops a directory from putting an escape sequence in a DN,
// and a hostile server must not be able to repaint the terminal through a name
// PADL displays.
//
// Two things keep that from happening — escape() strips control runes, and
// tview drops them again when it draws — so this passes with either one alone.
// It is here to catch the day one of them stops being true.
func TestTreeLabelsCannotCarryTerminalEscapes(t *testing.T) {
	d := sampleDir()
	base := "dc=example,dc=com"
	hostile := "cn=\x1b[2J\u009b6nevil," + base
	d.children[base] = append(d.children[base], newEntry(hostile, attr("objectClass", "device")))
	d.entries[hostile] = ptr(newEntry(hostile, attr("objectClass", "device")))

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("evil")

	for _, r := range h.text() {
		if r == '\n' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			t.Fatalf("control rune %#U reached the screen:\n%q", r, h.text())
		}
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

// A container bigger than one page offers to load the rest, rather than
// silently stopping.
func TestPagedContainerOffersToLoadMore(t *testing.T) {
	d := withManyUsers(sampleDir(), 10)

	p := testProfile()
	p.PageSize = 4
	h := start(t, p, okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.key(tcell.KeyRight)
	h.waitFor("4 so far, enter for more")

	// The first page is on screen and the rest is not, yet.
	screen := h.text()
	if !strings.Contains(screen, "uid=user00") {
		t.Errorf("first page missing:\n%s", screen)
	}
	if strings.Contains(screen, "uid=user09") {
		t.Errorf("the last page should not be loaded yet:\n%s", screen)
	}

	h.loadAllPages("uid=user")
	h.waitFor("uid=user09")

	// Once everything is loaded the offer goes away, and nothing is duplicated.
	h.waitUntil("the load-more row to disappear", func() bool {
		return !strings.Contains(h.text(), "enter for more")
	})
	if n := strings.Count(h.text(), "uid=user00"); n != 1 {
		t.Errorf("uid=user00 appears %d times; paging duplicated a row:\n%s", n, h.text())
	}
}

// A server without RFC 2696 cannot be asked for the rest, so the message has to
// say so and point at the only lever there is.
func TestUnpagedServerSaysItCannotFetchTheRest(t *testing.T) {
	d := withManyUsers(sampleDir(), 10)
	d.noPaging = true

	p := testProfile()
	p.PageSize = 3
	h := start(t, p, okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("first 3 only (no paging)")
	h.waitFor("this server has no paged results", "raise the profile's child limit")

	if strings.Contains(h.text(), "enter for more") {
		t.Error("there is no more to load on a server without paging; do not offer it")
	}
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
	h.waitFor("12345678-1234-5678-1234-56789abcdef0")

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
	// Something from the last section too, to prove the whole thing fits rather
	// than just the first screenful.
	h.waitFor("Keys (esc to close)", "quick search", "PADL_PASSWORD_<ID>")

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
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	// A member is a link; the free-text description is not.
	screen := h.text()
	// Links carry no trailing label — that would repeat down every member of a
	// large group. They are underlined instead, which is what has to be
	// asserted.
	if !h.isLink("uid=jdoe,ou=People,dc=example,dc=com") {
		t.Errorf("member should render as a link:\n%s", screen)
	}
	if h.isLink("The engineering team") {
		t.Errorf("free text must not become a link:\n%s", screen)
	}
	// A DN outside every naming context is not navigable, so not a link.
	if h.isLink("cn=other,dc=elsewhere,dc=net") {
		t.Errorf("a DN outside the tree must not become a link:\n%s", screen)
	}

	h.key(tcell.KeyTab)
	h.selectValueRow("uid=jdoe,ou=People,dc=example,dc=com")
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
	h.selectValueRow("cn=engineers,ou=Groups,dc=example,dc=com")
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
	if h.isLink("cn=admin,dc=hidden,dc=com") {
		t.Errorf("an unreachable DN must not be offered as a link:\n%s", h.text())
	}
}

// A link into a container bigger than one page must still land on the entry:
// the jump keeps pulling pages until it finds it, rather than giving up at the
// first page and leaving the cursor at the root.
func TestFollowDNPagesUntilItFindsTheEntry(t *testing.T) {
	d := withGroup(withManyUsers(sampleDir(), 10))
	people := "ou=People,dc=example,dc=com"
	engineers := "cn=engineers,ou=Groups,dc=example,dc=com"
	target := fmt.Sprintf("uid=user09,%s", people)
	d.entries[engineers].Attributes = append(d.entries[engineers].Attributes, attr("member", target))

	p := testProfile()
	p.PageSize = 2 // five pages before user09 shows up
	h := start(t, p, okConnector(d), nil)
	h.waitFor("ou=Groups")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	h.key(tcell.KeyTab)
	h.selectValueRow(target)
	h.key(tcell.KeyEnter)

	h.waitFor("dn: uid=user09,ou=People,dc=example,dc=com")
	h.waitFor("[u] uid=user09")
	if !h.rowHighlighted("[u] uid=user09", 2*time.Second) {
		t.Errorf("the jump should leave the cursor on the entry:\n%s", h.text())
	}
}

// When the tree genuinely cannot show the entry — the server will not page —
// the entry is loaded on its own rather than the jump appearing to do nothing.
func TestFollowDNShowsTheEntryWhenTheTreeCannotReachIt(t *testing.T) {
	d := withGroup(withManyUsers(sampleDir(), 10))
	d.noPaging = true
	people := "ou=People,dc=example,dc=com"
	engineers := "cn=engineers,ou=Groups,dc=example,dc=com"
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
	h.selectValueRow(target)
	h.key(tcell.KeyEnter)

	// The object pane shows it, and the status says why it has no row.
	h.waitFor("dn: uid=user09,ou=People,dc=example,dc=com")
	h.waitFor("showing it on its own")
}

// A member that does not exist is a different thing from one that is merely
// unloaded, and must still be reported as missing.
func TestFollowDNReportsAnEntryThatIsGenuinelyMissing(t *testing.T) {
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
	h.selectValueRow(ghost)
	h.key(tcell.KeyEnter)

	h.waitFor("uid=ghost,ou=People,dc=example,dc=com does not exist under ou=People,dc=example,dc=com")
}

// ------------------------------------------------------------------ search

func TestSearchFindsAnEntryAndJumpsToItInTheTree(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	// The bar says what it will search and where, so the base is never a guess.
	h.waitFor("filter", "scope sub", "under dc=example,dc=com")

	h.typeString("(uid=asmith)")
	h.key(tcell.KeyEnter)

	// Results replace the tree on the left.
	h.waitFor("1 for (uid=asmith)", "uid=asmith,ou=People,dc=example,dc=com")
	// Moving the cursor loads the entry on the right.
	h.waitFor("dn: uid=asmith,ou=People,dc=example,dc=com", "Alice Smith")

	// Enter takes it back into the tree, expanding ou=People on the way.
	h.key(tcell.KeyEnter)
	h.waitFor("[u] uid=asmith")
	if !h.rowHighlighted("[u] uid=asmith", 2*time.Second) {
		t.Errorf("the chosen result should be selected in the tree:\n%s", h.text())
	}
	if strings.Contains(h.text(), "1 for (uid=asmith)") {
		t.Errorf("the results pane should have given way to the tree:\n%s", h.text())
	}
}

func TestSearchEscapeReturnsToTheTree(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	// Escaping the filter bar leaves the tree alone.
	h.rune('/')
	h.waitFor("filter")
	h.key(tcell.KeyEscape)
	h.waitUntil("the filter bar to close", func() bool {
		return !strings.Contains(h.text(), "ctrl-s scope")
	})
	h.waitFor("[/] dc=example,dc=com")

	// Escaping the results goes back to the tree too.
	h.rune('/')
	h.typeString("(uid=jdoe)")
	h.key(tcell.KeyEnter)
	h.waitFor("1 for (uid=jdoe)")
	h.key(tcell.KeyEscape)
	h.waitUntil("the results to close", func() bool {
		return !strings.Contains(h.text(), "1 for (uid=jdoe)")
	})
	h.waitFor("[/] dc=example,dc=com", "ou=People")
}

func TestSearchWithNoMatchesSaysSo(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("(uid=nobody)")
	h.key(tcell.KeyEnter)

	h.waitFor("nothing matched")
	h.waitFor("matched nothing under dc=example,dc=com")
}

// A filter the server rejects has to be shown in full, not reduced to a blank
// result the user reads as "no matches".
func TestSearchFailureIsShownInADialog(t *testing.T) {
	d := withGroup(sampleDir())
	d.searchErr = errors.New("LDAP result 87 (Filter Error): invalid filter syntax")

	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("(uid=")
	h.key(tcell.KeyEnter)

	h.waitFor("Search failed", "Filter Error", "invalid filter syntax")
}

func TestSearchHistoryWalksBackAndForth(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	for _, filter := range []string{"(uid=jdoe)", "(uid=asmith)"} {
		h.rune('/')
		h.waitFor("filter")
		h.typeString(filter)
		h.key(tcell.KeyEnter)
		h.waitFor("1 for " + filter)
		h.key(tcell.KeyEscape)
	}

	h.rune('/')
	h.waitFor("filter")
	// Newest first.
	h.key(tcell.KeyUp)
	h.waitFor("(uid=asmith)")
	h.key(tcell.KeyUp)
	h.waitFor("(uid=jdoe)")
	// Forward again, and past the end back to the empty draft.
	h.key(tcell.KeyDown)
	h.waitFor("(uid=asmith)")
}

// Ctrl-S changes the scope without disturbing what has been typed.
func TestSearchScopeCyclesWithoutLosingTheFilter(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.waitFor("scope sub")
	h.typeString("(uid=jdoe)")

	h.screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)
	h.waitFor("scope base")
	h.screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)
	h.waitFor("scope one")

	if !strings.Contains(h.text(), "(uid=jdoe)") {
		t.Errorf("cycling the scope lost the filter:\n%s", h.text())
	}
}

// The base is whatever the tree has selected, so a search from inside a
// container is naturally narrowed to it.
func TestSearchBaseFollowsTheTreeSelection(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.waitFor("dn: ou=People,dc=example,dc=com")

	h.rune('/')
	h.waitFor("under ou=People,dc=example,dc=com")
}

// Search results bigger than a page offer the rest, the same way the tree does.
func TestSearchResultsPageOnDemand(t *testing.T) {
	d := withManyUsers(sampleDir(), 10)
	p := testProfile()
	p.PageSize = 4

	h := start(t, p, okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("(uid=user)")
	h.key(tcell.KeyEnter)

	h.waitFor("4 so far, enter for more")
	if strings.Contains(h.text(), "uid=user09") {
		t.Errorf("only the first page should be listed:\n%s", h.text())
	}

	h.loadAllPages("uid=user")

	h.waitFor("uid=user09")
	if n := strings.Count(h.text(), "uid=user00,"); n != 1 {
		t.Errorf("uid=user00 listed %d times; paging duplicated a row:\n%s", n, h.text())
	}
}

func TestSearchNeedsAConnection(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('c') // disconnect
	h.waitFor("disconnected")
	h.rune('/')
	h.waitFor("not connected")
}

// -------------------------------------------------------- bookmarks and LDIF

func TestBookmarkRoundTripThroughTheUI(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.waitFor("dn: ou=People,dc=example,dc=com")
	h.rune('b')
	h.waitFor("bookmarked ou=People,dc=example,dc=com")

	// It reached the profile store, not just the screen.
	p, ok := h.profiles.Get("lab")
	if !ok || !p.Bookmarked("ou=People,dc=example,dc=com") {
		t.Fatalf("the bookmark did not reach the profile: %+v", p.Bookmarks)
	}

	// And it comes back as a way to navigate.
	h.rune('B')
	h.waitFor("Bookmarks — Lab", "ou=People,dc=example,dc=com")
	h.key(tcell.KeyEnter)
	h.waitFor("dn: ou=People,dc=example,dc=com")

	// Pressing b again removes it.
	h.rune('b')
	h.waitFor("removed the bookmark")
	p, _ = h.profiles.Get("lab")
	if p.Bookmarked("ou=People,dc=example,dc=com") {
		t.Error("the bookmark should be gone from the profile")
	}
}

func TestBookmarkJumpsToADeepEntry(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	// Bookmark a deep entry, go elsewhere, then come back through the list.
	p, _ := h.profiles.Get("lab")
	p.AddBookmark("uid=jdoe,ou=People,dc=example,dc=com")
	if err := h.profiles.Put(p); err != nil {
		t.Fatalf("seed bookmark: %v", err)
	}
	// The app holds its own copy of the profile, so reconnect to pick it up.
	h.rune('c')
	h.waitFor("disconnected")
	h.rune('c')
	h.waitFor("Servers")
	h.key(tcell.KeyEnter)
	h.waitConnected()
	h.waitFor("ou=People")

	h.rune('B')
	h.waitFor("uid=jdoe,ou=People,dc=example,dc=com")
	h.key(tcell.KeyEnter)

	// ou=People was closed; the jump has to open it.
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com", "John Doe")
	h.waitFor("[u] uid=jdoe")
}

func TestGoToDNPrompt(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('g')
	h.waitFor("Go to DN")
	h.typeString("uid=asmith,ou=People,dc=example,dc=com")
	h.key(tcell.KeyTab) // off the field, onto OK
	h.key(tcell.KeyEnter)

	h.waitFor("dn: uid=asmith,ou=People,dc=example,dc=com", "Alice Smith")
	h.waitFor("[u] uid=asmith")
}

func TestExportSubtreeWritesLDIF(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	out := filepath.Join(t.TempDir(), "people.ldif")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.waitFor("dn: ou=People,dc=example,dc=com")
	h.rune('E')
	h.waitFor("Export subtree to LDIF")

	// The suggested name is derived from the RDN; replace it with our path.
	h.screen.InjectKey(tcell.KeyCtrlU, 0, tcell.ModNone)
	for i := 0; i < 40; i++ {
		h.screen.InjectKey(tcell.KeyBackspace2, 0, tcell.ModNone)
	}
	h.typeString(out)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)

	h.waitFor("wrote", "entries to")
	h.waitUntil("the file to exist", func() bool {
		_, err := os.Stat(out)
		return err == nil
	})

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	text := string(data)

	if !strings.HasPrefix(text, "# exported by PADL") {
		t.Errorf("export has no provenance header:\n%s", text)
	}
	if !strings.Contains(text, "version: 1") {
		t.Errorf("export has no LDIF version line:\n%s", text)
	}
	// The subtree root and its children, but nothing from a sibling container.
	for _, want := range []string{
		"dn: ou=People,dc=example,dc=com",
		"dn: uid=jdoe,ou=People,dc=example,dc=com",
		"dn: uid=asmith,ou=People,dc=example,dc=com",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("export is missing %q:\n%s", want, text)
		}
	}
	// The sibling container is not exported. Its DN does appear as a memberOf
	// value on the exported users, which is why this checks for the record
	// rather than the string.
	if strings.Contains(text, "dn: cn=engineers") {
		t.Errorf("export reached outside the selected subtree:\n%s", text)
	}
	if !strings.Contains(text, "memberOf: cn=engineers,ou=Groups,dc=example,dc=com") {
		t.Errorf("attribute values pointing outside the subtree should still be written:\n%s", text)
	}
}

// An export must never quietly overwrite something already there.
func TestExportRefusesToOverwrite(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	out := filepath.Join(t.TempDir(), "taken.ldif")
	if err := os.WriteFile(out, []byte("do not lose me"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.waitFor("dn: ou=People,dc=example,dc=com")
	h.rune('E')
	h.waitFor("Export subtree to LDIF")
	for i := 0; i < 40; i++ {
		h.screen.InjectKey(tcell.KeyBackspace2, 0, tcell.ModNone)
	}
	h.typeString(out)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)

	h.waitFor("Export failed", "cannot write", "exists")

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "do not lose me" {
		t.Errorf("the existing file was overwritten: %q", data)
	}
}

// -------------------------------------------------------------- quick search

// Bare words become a filter; the preview shows exactly what will run, so it is
// never guesswork.
func TestQuickSearchPreviewsTheFilterItWillRun(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	// The attributes are named before anything is typed: which ones a bare-word
	// search covers is what differs between servers.
	h.waitFor("words match", "cn sn givenName displayName uid mail ou o description")

	h.typeString("jdoe")
	h.waitFor("any of", "cn sn givenName displayName uid mail ou o description")

	// A second word says that both must match.
	h.typeString(" doe")
	h.waitFor("all 2 words, each in any of")

	// A raw filter is not rewritten.
	for i := 0; i < 10; i++ {
		h.screen.InjectKey(tcell.KeyBackspace2, 0, tcell.ModNone)
	}
	h.typeString("(uid=x)")
	h.waitFor("raw filter, sent as typed")
}

func TestQuickSearchFindsAnEntry(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("asmith")
	h.key(tcell.KeyEnter)

	// The results are titled with the words typed, not the enormous filter.
	h.waitFor("1 for asmith", "uid=asmith,ou=People,dc=example,dc=com")
	h.waitFor("dn: uid=asmith,ou=People,dc=example,dc=com", "Alice Smith")
}

// Two words have to narrow the result, not widen it.
func TestQuickSearchWithTwoTermsNarrows(t *testing.T) {
	d := withManyUsers(sampleDir(), 10)
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("user")
	h.key(tcell.KeyEnter)
	h.waitFor("10 for user")
	h.key(tcell.KeyEscape)

	h.rune('/')
	h.typeString("user 07")
	h.key(tcell.KeyEnter)
	h.waitFor("1 for user 07", "uid=user07")
}

// Anything starting with "(" is still a filter written by hand.
func TestRawFilterStillWorksAlongsideQuickSearch(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("(uid=jdoe)")
	h.waitFor("raw filter, sent as typed")
	h.key(tcell.KeyEnter)

	h.waitFor("1 for (uid=jdoe)", "uid=jdoe,ou=People,dc=example,dc=com")
}

// ---------------------------------------------------------------- history

// Back and forward retrace deliberate jumps, the way a browser does. Scrolling
// the tree is reading, not navigating, so it does not enter the history.
func TestHistoryBackAndForward(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	// Browse manually to the group, then follow a member link.
	h.key(tcell.KeyDown) // ou=Groups
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	h.key(tcell.KeyTab)
	h.selectValueRow("uid=jdoe,ou=People,dc=example,dc=com")
	h.key(tcell.KeyEnter)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")

	// From the user, follow memberOf back to the group — a second jump.
	h.key(tcell.KeyTab)
	h.selectValueRow("cn=engineers,ou=Groups,dc=example,dc=com")
	h.key(tcell.KeyEnter)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	// Back to the user.
	h.rune('<')
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")
	// Back again to where the browsing started.
	h.rune('<')
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	// And forward through the same trail.
	h.rune('>')
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")
	h.rune('>')
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")
}

func TestHistoryAtTheEndsSaysSo(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('<')
	h.waitFor("nothing to go back to")
	h.rune('>')
	h.waitFor("nothing to go forward to")
}

// A new jump after going back drops the forward trail, the same as a browser
// following a link after the back button.
func TestHistoryForwardIsDroppedByANewJump(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	h.key(tcell.KeyTab)
	h.selectValueRow("uid=jdoe,ou=People,dc=example,dc=com")
	h.key(tcell.KeyEnter)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")

	h.rune('<')
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com")

	// A fresh jump from here: forward should no longer lead to jdoe.
	h.rune('g')
	h.waitFor("Go to DN")
	h.typeString("uid=asmith,ou=People,dc=example,dc=com")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("dn: uid=asmith,ou=People,dc=example,dc=com")

	h.rune('>')
	h.waitFor("nothing to go forward to")
}

// Alt-Left and Alt-Right do the same thing, for people who reach for the
// browser bindings.
func TestHistoryAltArrowBindings(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('g')
	h.waitFor("Go to DN")
	h.typeString("uid=jdoe,ou=People,dc=example,dc=com")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")

	h.screen.InjectKey(tcell.KeyLeft, 0, tcell.ModAlt)
	h.waitFor("dn: dc=example,dc=com")
	h.screen.InjectKey(tcell.KeyRight, 0, tcell.ModAlt)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")
}

// Reconnecting starts a fresh trail: the old one points into a tree that is no
// longer on screen.
func TestHistoryResetsOnReconnect(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('g')
	h.waitFor("Go to DN")
	h.typeString("uid=jdoe,ou=People,dc=example,dc=com")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com")

	h.rune('c')
	h.waitFor("disconnected")
	h.rune('c')
	h.waitFor("Servers")
	h.key(tcell.KeyEnter)
	h.waitConnected()
	h.waitFor("ou=People")

	h.rune('<')
	h.waitFor("nothing to go back to")
}

// History keys while disconnected must say why nothing happened, rather than
// doing nothing at all.
func TestHistoryWhileDisconnectedSaysSo(t *testing.T) {
	d := withGroup(sampleDir())
	h := start(t, testProfile(), okConnector(d), nil)
	h.waitFor("ou=People")

	h.rune('c')
	h.waitFor("disconnected")

	h.rune('<')
	h.waitFor("not connected")
	h.rune('>')
	h.waitFor("not connected")
}
