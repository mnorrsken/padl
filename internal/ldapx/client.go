package ldapx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/mnorrsken/padl/internal/config"
)

// OIDPagedResults is RFC 2696, checked before PADL relies on paging.
const OIDPagedResults = "1.2.840.113556.1.4.319"

// Client is one connection to one directory server. It satisfies Directory.
//
// Every method takes a context and honours it, because the whole UI depends on
// being able to abandon a slow search without freezing the terminal.
type Client struct {
	profile config.Profile
	vendor  Vendor
	root    *RootDSE

	mu   sync.Mutex
	conn *ldap.Conn
}

var _ Directory = (*Client)(nil)

// Connect dials, upgrades to TLS if configured, and binds.
//
// pin is the profile's currently trusted certificate, or nil if none. On a
// certificate the operator has to judge, Connect returns a *CertTrustError and
// nothing else happens — the caller shows the prompt and, on acceptance, calls
// Connect again with the new pin. That retry is why Connect keeps no state of
// its own until it fully succeeds.
func Connect(ctx context.Context, p config.Profile, pin *config.Pin, password string) (*Client, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	timeout := time.Duration(p.Timeout()) * time.Second
	capture := &trustCapture{}
	tlsCfg := tlsConfigFor(hostForVerify(p.Host), pin, capture)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := ldap.DialURL(p.URL(), ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, trustOrDialError(err, capture, p)
	}

	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	if p.Security == config.SecurityStartTLS {
		// The upgrade uses the same verifier, so a StartTLS server gets exactly
		// the same trust decision an LDAPS one would.
		if err := conn.StartTLS(tlsCfg); err != nil {
			return nil, trustOrDialError(err, capture, p)
		}
	}

	conn.SetTimeout(timeout)

	if err := bind(conn, p, password); err != nil {
		return nil, err
	}

	c := &Client{profile: p, conn: conn}
	root, err := c.RootDSE(ctx)
	if err != nil {
		// A server that refuses the root DSE is still usable when the profile
		// names a base DN explicitly, which is the eDirectory-with-anonymous
		// case. Carry on with an empty root DSE rather than failing the connect.
		if p.BaseDN == "" {
			return nil, fmt.Errorf("read root DSE: %w", err)
		}
		root = &RootDSE{}
	}
	c.root = root
	c.vendor = DetectVendor(root)

	ok = true
	return c, nil
}

// trustOrDialError turns a failed handshake into the *CertTrustError the UI can
// act on. go-ldap wraps handshake failures, and the exact wrapping is not part
// of its contract, so the verifier's own record of its verdict is the fallback.
func trustOrDialError(err error, capture *trustCapture, p config.Profile) error {
	if cte, ok := AsCertTrustError(err); ok {
		return cte
	}
	if capture.err != nil {
		return capture.err
	}
	return fmt.Errorf("connect to %s: %w", p.Addr(), err)
}

// bind authenticates. Anonymous profiles send a genuine anonymous bind rather
// than skipping the bind entirely, so servers that reject it say so up front
// instead of failing later on the first search.
func bind(conn *ldap.Conn, p config.Profile, password string) error {
	if p.Bind == config.BindAnonymous {
		if err := conn.UnauthenticatedBind(""); err != nil {
			return fmt.Errorf("anonymous bind rejected by %s: %w", p.Addr(), redactBindError(err, password))
		}
		return nil
	}
	// Catch a bind name that is not a DN before it reaches the server. Servers
	// answer this with anything from invalidDNSyntax to namingViolation, and
	// none of those codes say the useful thing.
	if err := ValidateDN(p.BindDN); err != nil {
		return fmt.Errorf("bind as %s failed: %w", p.BindDN, err)
	}
	if err := conn.Bind(p.BindDN, password); err != nil {
		return fmt.Errorf("bind as %s failed: %w", p.BindDN, redactBindError(err, password))
	}
	return nil
}

// ValidateDN reports whether s is a syntactically valid distinguished name.
//
// The message names the mistake people actually make — typing a bare username
// where a DN belongs — because the LDAP result codes for it are unhelpful and
// vary by server.
func ValidateDN(s string) error {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return errors.New("the bind DN is empty")
	}
	if _, err := ldap.ParseDN(trimmed); err != nil {
		if !strings.Contains(trimmed, "=") {
			return fmt.Errorf("%q is not a distinguished name — a bind DN looks like "+
				"uid=admin,ou=people,dc=example,dc=com or cn=admin,dc=example,dc=com", trimmed)
		}
		return fmt.Errorf("%q is not a valid distinguished name: %w", trimmed, err)
	}
	return nil
}

// redactBindError keeps the LDAP result code *and* the server's own diagnostic
// text, which is often the only thing that says what went wrong — lldap, for
// one, answers a wrong bind DN with the exact shape it expects. The password is
// scrubbed from the text defensively, so nothing a server echoes back can put
// it on screen or in a log.
func redactBindError(err error, password string) error {
	var le *ldap.Error
	if !errors.As(err, &le) {
		return errors.New(scrub(err.Error(), password))
	}
	msg := fmt.Sprintf("LDAP result %d (%s)", le.ResultCode, ldap.LDAPResultCodeMap[le.ResultCode])
	if detail := serverDiagnostic(le); detail != "" {
		msg += ": " + detail
	}
	return errors.New(scrub(msg, password))
}

// serverDiagnostic pulls the diagnosticMessage out of an LDAP error, dropping
// go-ldap's own restatement of the result code.
func serverDiagnostic(le *ldap.Error) string {
	if le.Err == nil {
		return ""
	}
	detail := strings.TrimSpace(le.Err.Error())
	if detail == "" || strings.EqualFold(detail, ldap.LDAPResultCodeMap[le.ResultCode]) {
		return ""
	}
	return detail
}

// scrub removes a secret from a message. A short or empty password is left
// alone: blanking every occurrence of a two-character string would mangle the
// message without protecting anything.
func scrub(msg, secret string) string {
	if len(secret) < 4 {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "[redacted]")
}

// Profile is the profile this client was opened with.
func (c *Client) Profile() config.Profile { return c.profile }

// Vendor is the detected server implementation.
func (c *Client) Vendor() Vendor { return c.vendor }

// Root is the cached root DSE from connect time.
func (c *Client) Root() *RootDSE { return c.root }

// SupportsPaging reports whether the server advertised RFC 2696.
func (c *Client) SupportsPaging() bool { return c.root != nil && c.root.Supports(OIDPagedResults) }

// Close releases the connection. Closing twice is harmless.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (c *Client) live() (*ldap.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil, errors.New("not connected")
	}
	return c.conn, nil
}

// RootDSE reads the server's root DSE.
func (c *Client) RootDSE(ctx context.Context) (*RootDSE, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, c.profile.Timeout(), false, "(objectClass=*)", rootDSEAttrs, nil)
	entries, _, err := c.run(ctx, req, 1)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("server returned no root DSE")
	}
	return parseRootDSE(&entries[0]), nil
}

// childAttrs is the minimum needed to draw a tree row: the classes pick the
// icon and the subordinate hints decide whether to draw an expand marker
// without a second round trip per child.
var childAttrs = []string{"objectClass", "hasSubordinates", "numSubordinates", "subordinateCount"}

// Children lists the immediate subordinates of dn, one page at a time.
func (c *Client) Children(ctx context.Context, dn string, req PageRequest) (*Page, error) {
	page, err := c.Search(ctx, Query{
		BaseDN:     dn,
		Scope:      ScopeOneLevel,
		Filter:     "(objectClass=*)",
		Attributes: childAttrs,
	}, req)
	if err != nil {
		return nil, fmt.Errorf("list children of %s: %w", displayDN(dn), err)
	}
	page.Entries = directChildren(dn, page.Entries)
	SortEntries(page.Entries)
	return page, nil
}

// Search runs a query and returns one page of results.
func (c *Client) Search(ctx context.Context, q Query, req PageRequest) (*Page, error) {
	size := req.Size
	if size <= 0 {
		size = c.profile.Limit()
	}
	filter := strings.TrimSpace(q.Filter)
	if filter == "" {
		filter = "(objectClass=*)"
	}
	attrs := q.Attributes
	if len(attrs) == 0 {
		attrs = childAttrs
	}

	search := ldap.NewSearchRequest(q.BaseDN, scopeOf(q.Scope), ldap.NeverDerefAliases,
		0, c.profile.Timeout(), false, filter, attrs, nil)

	// Without RFC 2696 there is no way to ask for the rest, so the best that can
	// be done is to stop at the limit and say the result was cut short.
	if !c.SupportsPaging() {
		entries, truncated, err := c.run(ctx, search, size)
		if err != nil {
			return nil, searchError(q, err)
		}
		return &Page{Entries: entries, Truncated: truncated}, nil
	}

	paging := ldap.NewControlPaging(uint32(size))
	paging.SetCookie(req.Cookie)
	search.Controls = append(search.Controls, paging)

	// The size is a page size now, not a cap, so nothing is dropped: read the
	// whole page and hand back the cookie for the next one.
	entries, _, controls, err := c.runPaged(ctx, search, size)
	if err != nil {
		return nil, searchError(q, err)
	}
	return &Page{Entries: entries, Cookie: pagingCookie(controls)}, nil
}

// searchError wraps a failure with the query that caused it, since a bad filter
// is by far the most likely reason and the filter is what the user has to fix.
func searchError(q Query, err error) error {
	if strings.TrimSpace(q.Filter) != "" && q.Filter != "(objectClass=*)" {
		return fmt.Errorf("search %s under %s: %w", q.Filter, displayDN(q.BaseDN), err)
	}
	return fmt.Errorf("search under %s: %w", displayDN(q.BaseDN), err)
}

func scopeOf(s Scope) int {
	switch s {
	case ScopeBase:
		return ldap.ScopeBaseObject
	case ScopeOneLevel:
		return ldap.ScopeSingleLevel
	default:
		return ldap.ScopeWholeSubtree
	}
}

// pagingCookie digs the continuation cookie out of a searchResDone's controls.
// An absent control, or an empty cookie, both mean this was the last page.
func pagingCookie(controls []ldap.Control) []byte {
	ctrl := ldap.FindControl(controls, ldap.ControlTypePaging)
	paging, ok := ctrl.(*ldap.ControlPaging)
	if !ok || paging == nil || len(paging.Cookie) == 0 {
		return nil
	}
	return paging.Cookie
}

// directChildren reduces a one-level result to entries that really are one
// level down.
//
// Not every server honours the scope: lldap answers a one-level search at the
// tree root with the whole subtree, so the containers in between never appear
// and the tree comes out flat and wrong. Anything deeper than one level is
// folded back into the ancestor it belongs under, which is inferred from the
// DNs the server itself returned — nothing is invented. On a server that gets
// scope right this is a no-op.
func directChildren(parent string, entries []Entry) []Entry {
	var (
		out     []Entry
		real    = map[string]bool{}
		implied []string
		seen    = map[string]bool{}
	)
	for _, e := range entries {
		switch DepthUnder(e.DN, parent) {
		case 1:
			key := strings.ToLower(e.DN)
			if real[key] {
				continue
			}
			real[key] = true
			out = append(out, e)
		case -1, 0:
			// Not under this node at all, or the node itself. Neither belongs
			// in a list of its children.
			continue
		default:
			ancestor := AncestorUnder(e.DN, parent)
			key := strings.ToLower(ancestor)
			if ancestor == "" || seen[key] {
				continue
			}
			seen[key] = true
			implied = append(implied, ancestor)
		}
	}

	// A real entry always wins: the placeholder only exists to stand in for a
	// container the server declined to list.
	for _, dn := range implied {
		if real[strings.ToLower(dn)] {
			continue
		}
		has := true
		out = append(out, Entry{
			DN:              dn,
			Subordinates:    -1,
			HasSubordinates: &has,
			Synthesized:     true,
		})
	}
	return out
}

// Entry reads a single entry by DN. Operational attributes cost a second round
// trip and are only fetched when asked for, since most views never show them.
func (c *Client) Entry(ctx context.Context, dn string, operational bool) (*Entry, error) {
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, c.profile.Timeout(), false, "(objectClass=*)", []string{"*"}, nil)
	entries, _, err := c.run(ctx, req, 1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", displayDN(dn), err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no such entry: %s", displayDN(dn))
	}
	e, err := pickEntry(dn, entries)
	if err != nil {
		return nil, err
	}

	if operational {
		opReq := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, c.profile.Timeout(), false, "(objectClass=*)", []string{"+"}, nil)
		opEntries, _, opErr := c.run(ctx, opReq, 8)
		// Not every server supports "+". Losing the operational attributes is
		// not a reason to fail the whole read.
		if opErr == nil {
			if opEntry, pickErr := pickEntry(dn, opEntries); pickErr == nil {
				e.Attributes = append(e.Attributes, markOperational(e, opEntry.Attributes)...)
			}
		}
	}
	return e, nil
}

// pickEntry finds the requested DN among what a base-scope search returned.
//
// A base-scope read is meant to answer with exactly that entry, but lldap
// answers one at the tree root with the whole subtree instead. Taking the first
// result would then show a completely unrelated entry under the right heading,
// which is worse than saying nothing.
func pickEntry(dn string, entries []Entry) (*Entry, error) {
	for i := range entries {
		if EqualDN(entries[i].DN, dn) {
			return &entries[i], nil
		}
	}
	if len(entries) == 1 && strings.TrimSpace(dn) == "" {
		// The root DSE, whose DN servers may render in any number of ways.
		return &entries[0], nil
	}
	return nil, fmt.Errorf("%s: the server answered a base-scope read with %d other entr%s and none of them was this DN",
		displayDN(dn), len(entries), plural(len(entries), "y", "ies"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// markOperational returns the operational attributes not already present in the
// user-attribute set, flagged so the object pane can dim them.
func markOperational(user *Entry, ops []Attribute) []Attribute {
	have := map[string]bool{}
	for _, a := range user.Attributes {
		have[lower(a.Name)] = true
	}
	out := make([]Attribute, 0, len(ops))
	for _, a := range ops {
		if have[lower(a.Name)] {
			continue
		}
		a.Operational = true
		out = append(out, a)
	}
	return out
}

// run executes a search, collecting at most limit entries.
//
// It uses SearchAsync so that cancelling ctx actually stops the search rather
// than leaving the caller blocked; that is also how truncation is detected —
// consume one entry past the limit, then cancel.
func (c *Client) run(ctx context.Context, req *ldap.SearchRequest, limit int) ([]Entry, bool, error) {
	conn, err := c.live()
	if err != nil {
		return nil, false, err
	}

	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		entries   []Entry
		truncated bool
	)
	res := conn.SearchAsync(searchCtx, req, 64)
	for res.Next() {
		// Next reports true for messages that carry no entry — a referral, or a
		// searchResDone with a control attached, which lldap sends on every
		// search. Dereferencing those is a crash, so they are skipped here
		// rather than guarded further down. (Referral chasing is a later
		// milestone; for now they are simply not followed.)
		entry := res.Entry()
		if entry == nil {
			continue
		}
		if len(entries) >= limit {
			truncated = true
			cancel() // abandon the rest; the server has more than we will show
			break
		}
		entries = append(entries, convertEntry(entry))
	}
	// SearchAsync reports a cancelled search as success, so the caller's own
	// cancellation has to be checked explicitly.
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err := res.Err(); err != nil {
		return nil, false, err
	}
	return entries, truncated, nil
}

// runPaged is run() for a search carrying a paging control: it reads the whole
// page rather than stopping at a cap, and keeps the controls from the
// searchResDone message, which is where the continuation cookie lives.
func (c *Client) runPaged(ctx context.Context, req *ldap.SearchRequest, size int) ([]Entry, bool, []ldap.Control, error) {
	conn, err := c.live()
	if err != nil {
		return nil, false, nil, err
	}

	var (
		entries  []Entry
		controls []ldap.Control
	)
	res := conn.SearchAsync(ctx, req, 64)
	for res.Next() {
		entry := res.Entry()
		if entry == nil {
			// The entry-less message: a referral, or the searchResDone whose
			// controls carry the cookie. Keep whatever controls it had.
			if cs := res.Controls(); len(cs) > 0 {
				controls = cs
			}
			continue
		}
		entries = append(entries, convertEntry(entry))
	}
	if ctx.Err() != nil {
		return nil, false, nil, ctx.Err()
	}
	if err := res.Err(); err != nil {
		return nil, false, nil, err
	}
	return entries, len(entries) > size, controls, nil
}

// convertEntry maps a go-ldap entry onto PADL's own, keeping raw bytes so
// binary attributes survive intact.
func convertEntry(src *ldap.Entry) Entry {
	e := Entry{DN: src.DN, Subordinates: -1}
	e.Attributes = make([]Attribute, 0, len(src.Attributes))
	for _, a := range src.Attributes {
		values := a.ByteValues
		if len(values) == 0 && len(a.Values) > 0 {
			values = make([][]byte, len(a.Values))
			for i, v := range a.Values {
				values[i] = []byte(v)
			}
		}
		e.Attributes = append(e.Attributes, Attribute{Name: a.Name, Values: values})
	}
	applySubordinateHints(&e)
	return e
}

// applySubordinateHints reads whichever "do I have children" attribute this
// server happens to publish. AD and OpenLDAP answer hasSubordinates;
// numSubordinates is the AD spelling and subordinateCount the eDirectory one.
// When none of them come back, HasSubordinates stays nil and the tree treats
// the node as maybe-expandable.
func applySubordinateHints(e *Entry) {
	for _, name := range []string{"numSubordinates", "subordinateCount"} {
		if v := e.First(name); v != "" {
			if n, err := parseUint(v); err == nil {
				e.Subordinates = n
				has := n > 0
				e.HasSubordinates = &has
				return
			}
		}
	}
	if v := e.First("hasSubordinates"); v != "" {
		has := lower(v) == "true"
		e.HasSubordinates = &has
	}
}
