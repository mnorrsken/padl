package ldapx_test

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ldapx"
)

// These run against the throwaway OpenLDAP in dev/docker-compose.yml. They are
// skipped unless PADL_IT=1 so `go test ./...` stays fast and offline.
//
//	docker compose -f dev/docker-compose.yml up -d
//	PADL_IT=1 go test ./internal/ldapx/ -run Integration -v

const (
	itBaseDN   = "dc=example,dc=com"
	itAdminDN  = "cn=admin,dc=example,dc=com"
	itAdminPwd = "padl-lab"
)

func requireIT(t *testing.T) {
	t.Helper()
	if os.Getenv("PADL_IT") != "1" {
		t.Skip("set PADL_IT=1 and start dev/docker-compose.yml to run integration tests")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func itHost() string { return envOr("PADL_IT_HOST", "127.0.0.1") }

func itPort(t *testing.T, key, fallback string) int {
	t.Helper()
	n, err := strconv.Atoi(envOr(key, fallback))
	if err != nil {
		t.Fatalf("bad port in %s: %v", key, err)
	}
	return n
}

func itProfile(t *testing.T, security config.Security) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "it"
	p.Name = "Integration lab"
	p.Host = itHost()
	p.Security = security
	p.Bind = config.BindSimple
	p.BindDN = itAdminDN
	p.PasswordRef = config.PasswordPrompt
	p.TimeoutSeconds = 10
	if security == config.SecurityLDAPS {
		p.Port = itPort(t, "PADL_IT_LDAPS_PORT", "13636")
	} else {
		p.Port = itPort(t, "PADL_IT_LDAP_PORT", "13389")
	}
	return p
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestIntegrationPlainSimpleBind(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	root, err := c.RootDSE(ctx(t))
	if err != nil {
		t.Fatalf("root DSE: %v", err)
	}
	bases := root.Bases("", false)
	if len(bases) == 0 || !strings.EqualFold(bases[0], itBaseDN) {
		t.Fatalf("naming contexts = %v, want %s", bases, itBaseDN)
	}
	if c.Vendor() != ldapx.VendorOpenLDAP {
		t.Errorf("vendor = %v, want OpenLDAP", c.Vendor())
	}
}

// The lab keeps OpenLDAP's default ACLs, which let anyone read the root DSE but
// hide the data itself from an unauthenticated client. That is the common
// real-world shape, and it is what makes the profile's base DN override matter:
// an anonymous connect can discover the naming contexts even when it cannot
// read a single entry under them.
func TestIntegrationAnonymousBind(t *testing.T) {
	requireIT(t)
	p := itProfile(t, config.SecurityNone)
	p.Bind = config.BindAnonymous
	p.BindDN = ""
	p.PasswordRef = ""

	c, err := ldapx.Connect(ctx(t), p, nil, "")
	if err != nil {
		t.Fatalf("anonymous connect: %v", err)
	}
	defer c.Close()

	root, err := c.RootDSE(ctx(t))
	if err != nil {
		t.Fatalf("anonymous root DSE: %v", err)
	}
	if bases := root.Bases("", false); len(bases) == 0 {
		t.Error("the root DSE should be readable anonymously")
	}
}

func TestIntegrationWrongPasswordIsRejectedWithoutLeakingIt(t *testing.T) {
	requireIT(t)
	_, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, "not-the-password")
	if err == nil {
		t.Fatal("a wrong password should not connect")
	}
	if strings.Contains(err.Error(), "not-the-password") {
		t.Errorf("the password leaked into the error text: %v", err)
	}
}

func TestIntegrationBrowseTree(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	page, err := c.Children(ctx(t), itBaseDN, ldapx.PageRequest{Size: 100})
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if page.More() {
		t.Error("the seed tree is small; one page should hold it")
	}
	rdns := map[string]bool{}
	for _, e := range page.Entries {
		rdns[e.RDN()] = true
	}
	for _, want := range []string{"ou=People", "ou=Groups"} {
		if !rdns[want] {
			t.Errorf("children of %s = %v, want it to include %s", itBaseDN, rdns, want)
		}
	}
}

// Paging against a real server: a page size of one has to walk the container an
// entry at a time and end with an empty cookie, having seen everything exactly
// once.
func TestIntegrationPagedChildren(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if !c.SupportsPaging() {
		t.Fatal("the lab OpenLDAP advertises RFC 2696; something is wrong with the check")
	}

	people := "ou=People," + itBaseDN
	seen := map[string]int{}
	req := ldapx.PageRequest{Size: 1}
	pages := 0
	for {
		page, err := c.Children(ctx(t), people, req)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		for _, e := range page.Entries {
			seen[strings.ToLower(e.DN)]++
		}
		if !page.More() {
			break
		}
		if pages > 20 {
			t.Fatal("paging did not terminate")
		}
		req = page.Next(1)
	}

	if pages < 2 {
		t.Errorf("a page size of 1 over two users should take more than one page, took %d", pages)
	}
	for _, want := range []string{"uid=jdoe," + people, "uid=asmith," + people} {
		if seen[strings.ToLower(want)] != 1 {
			t.Errorf("%s seen %d times across pages, want exactly 1", want, seen[strings.ToLower(want)])
		}
	}
}

// Search is what the filter bar runs.
func TestIntegrationSearch(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	page, err := c.Search(ctx(t), ldapx.Query{
		BaseDN: itBaseDN,
		Scope:  ldapx.ScopeSubtree,
		Filter: "(uid=jdoe)",
	}, ldapx.PageRequest{Size: 50})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("(uid=jdoe) matched %d entries, want 1", len(page.Entries))
	}
	if !strings.EqualFold(page.Entries[0].DN, "uid=jdoe,ou=People,"+itBaseDN) {
		t.Errorf("matched %s", page.Entries[0].DN)
	}

	// A subtree search from the root reaches entries a one-level search cannot.
	deep, err := c.Search(ctx(t), ldapx.Query{
		BaseDN: itBaseDN,
		Scope:  ldapx.ScopeSubtree,
		Filter: "(objectClass=inetOrgPerson)",
	}, ldapx.PageRequest{Size: 50})
	if err != nil {
		t.Fatalf("subtree search: %v", err)
	}
	if len(deep.Entries) < 2 {
		t.Errorf("subtree search found %d people, want both seeded ones", len(deep.Entries))
	}

	// A malformed filter must come back as an error, not as an empty result.
	if _, err := c.Search(ctx(t), ldapx.Query{
		BaseDN: itBaseDN,
		Scope:  ldapx.ScopeSubtree,
		Filter: "(uid=",
	}, ldapx.PageRequest{Size: 10}); err == nil {
		t.Error("a malformed filter should be reported, not silently matched")
	}
}

func TestIntegrationReadEntry(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	dn := "uid=jdoe,ou=People," + itBaseDN
	e, err := c.Entry(ctx(t), dn, false)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if got := e.First("cn"); got != "John Doe" {
		t.Errorf("cn = %q, want John Doe", got)
	}
	if got := e.Get("mail"); len(got) != 2 {
		t.Errorf("mail = %v, want both seeded values", got)
	}
	if hasAttr(e, "createTimestamp") {
		t.Error("operational attributes should not come back unless asked for")
	}

	withOps, err := c.Entry(ctx(t), dn, true)
	if err != nil {
		t.Fatalf("read entry with operational: %v", err)
	}
	if !hasAttr(withOps, "createTimestamp") {
		t.Error("createTimestamp should be present when operational attributes are requested")
	}
	for _, a := range withOps.Attributes {
		if strings.EqualFold(a.Name, "createTimestamp") && !a.Operational {
			t.Error("createTimestamp should be flagged operational so the pane can dim it")
		}
	}

	if _, err := c.Entry(ctx(t), "uid=nobody,ou=People,"+itBaseDN, false); err == nil {
		t.Error("reading a missing entry should fail")
	}
}

func hasAttr(e *ldapx.Entry, name string) bool {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return true
		}
	}
	return false
}

// The lab's certificate is self-signed and issued for the container hostname,
// so connecting to 127.0.0.1 exercises the full trust-on-first-use path against
// a real TLS handshake rather than a hand-built error.
func TestIntegrationLDAPSTrustOnFirstUse(t *testing.T) {
	requireIT(t)
	p := itProfile(t, config.SecurityLDAPS)

	_, err := ldapx.Connect(ctx(t), p, nil, itAdminPwd)
	cte, ok := ldapx.AsCertTrustError(err)
	if !ok {
		t.Fatalf("first LDAPS connect should ask about the certificate, got %v", err)
	}
	if cte.Reason != ldapx.TrustUntrusted {
		t.Errorf("Reason = %v, want TrustUntrusted", cte.Reason)
	}
	if cte.Fingerprint == "" {
		t.Error("the prompt needs a fingerprint to show")
	}

	pin := cte.Pin()
	c, err := ldapx.Connect(ctx(t), p, &pin, itAdminPwd)
	if err != nil {
		t.Fatalf("connect with the pin should succeed: %v", err)
	}
	defer c.Close()

	if _, err := c.Children(ctx(t), itBaseDN, ldapx.PageRequest{Size: 10}); err != nil {
		t.Fatalf("search over LDAPS: %v", err)
	}

	// A pin that does not match must be reported as a change, not waved through.
	wrong := pin
	wrong.Fingerprint = strings.Repeat("AA:", 31) + "AA"
	_, err = ldapx.Connect(ctx(t), p, &wrong, itAdminPwd)
	changed, ok := ldapx.AsCertTrustError(err)
	if !ok {
		t.Fatalf("a mismatched pin should raise a trust error, got %v", err)
	}
	if changed.Reason != ldapx.TrustChanged {
		t.Errorf("Reason = %v, want TrustChanged", changed.Reason)
	}
	if changed.Existing == nil || changed.Existing.Fingerprint != wrong.Fingerprint {
		t.Error("the prompt should carry the pin that failed to match")
	}
}

func TestIntegrationStartTLSTrustOnFirstUse(t *testing.T) {
	requireIT(t)
	p := itProfile(t, config.SecurityStartTLS)

	_, err := ldapx.Connect(ctx(t), p, nil, itAdminPwd)
	cte, ok := ldapx.AsCertTrustError(err)
	if !ok {
		t.Fatalf("first StartTLS connect should ask about the certificate, got %v", err)
	}

	pin := cte.Pin()
	c, err := ldapx.Connect(ctx(t), p, &pin, itAdminPwd)
	if err != nil {
		t.Fatalf("StartTLS with the pin should succeed: %v", err)
	}
	defer c.Close()

	if _, err := c.Children(ctx(t), itBaseDN, ldapx.PageRequest{Size: 10}); err != nil {
		t.Fatalf("search over StartTLS: %v", err)
	}
}

func TestIntegrationContextCancellationStopsASearch(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Children(cancelled, itBaseDN, ldapx.PageRequest{Size: 100}); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context should abandon the search, got %v", err)
	}
}

// ---------------------------------------------------------------------- lldap

// lldap only accepts bind DNs shaped uid=<id>,ou=people,<base> and answers
// anything else with a naming violation whose diagnostic names the expected
// shape. That diagnostic is the whole reason PADL keeps server error text.

const itLLDAPAdminDN = "uid=admin,ou=people,dc=example,dc=com"

func itLLDAPProfile(t *testing.T) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "it-lldap"
	p.Name = "lldap lab"
	p.Host = itHost()
	p.Port = itPort(t, "PADL_IT_LLDAP_PORT", "13390")
	p.Security = config.SecurityNone
	p.Bind = config.BindSimple
	p.BindDN = itLLDAPAdminDN
	p.PasswordRef = config.PasswordPrompt
	p.TimeoutSeconds = 10
	return p
}

func TestIntegrationLLDAPBindAndBrowse(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itLLDAPProfile(t), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if c.Vendor() != ldapx.VendorLLDAP {
		t.Errorf("vendor = %v, want lldap", c.Vendor())
	}

	root, err := c.RootDSE(ctx(t))
	if err != nil {
		t.Fatalf("root DSE: %v", err)
	}
	if bases := root.Bases("", false); len(bases) == 0 || !strings.EqualFold(bases[0], itBaseDN) {
		t.Fatalf("naming contexts = %v, want %s", bases, itBaseDN)
	}

	page, err := c.Children(ctx(t), itBaseDN, ldapx.PageRequest{Size: 100})
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	rdns := map[string]bool{}
	for _, e := range page.Entries {
		rdns[strings.ToLower(e.RDN())] = true
	}
	if !rdns["ou=people"] {
		t.Errorf("children of %s = %v, want ou=people", itBaseDN, rdns)
	}

	e, err := c.Entry(ctx(t), itLLDAPAdminDN, false)
	if err != nil {
		t.Fatalf("read admin: %v", err)
	}
	if got := e.First("uid"); !strings.EqualFold(got, "admin") {
		t.Errorf("uid = %q, want admin", got)
	}
}

// The failure the user actually hits: a bind DN in the wrong shape. PADL must
// pass the server's explanation through rather than reduce it to a code.
func TestIntegrationLLDAPWrongDNShapeKeepsTheDiagnostic(t *testing.T) {
	requireIT(t)
	p := itLLDAPProfile(t)
	p.BindDN = "cn=admin,dc=example,dc=com"

	_, err := ldapx.Connect(ctx(t), p, nil, itAdminPwd)
	if err == nil {
		t.Fatal("a bind DN in the wrong shape should be rejected")
	}
	msg := err.Error()
	if !strings.Contains(msg, "LDAP result 64") {
		t.Errorf("the result code should be reported, got %q", msg)
	}
	if !strings.Contains(msg, "uid=id,ou=people") {
		t.Errorf("the server's diagnostic names the expected DN shape and must survive, got %q", msg)
	}
}

// A bare username goes to the server like any other bind name, because only the
// server knows which ones it takes — Active Directory accepts two that are not
// DNs at all. lldap does not, and says so in terms worth passing on.
func TestIntegrationLLDAPBareUsernameGetsTheServersAnswer(t *testing.T) {
	requireIT(t)
	p := itLLDAPProfile(t)
	p.BindDN = "admin"

	_, err := ldapx.Connect(ctx(t), p, nil, itAdminPwd)
	if err == nil {
		t.Fatal("lldap does not accept a bare username as a bind name")
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Errorf("the error should name the bind that failed, got %q", err)
	}
	// lldap answers this one with "Missing DN value", which is the only part
	// that tells anyone what to type instead.
	if !strings.Contains(strings.ToLower(err.Error()), "dn") {
		t.Errorf("the server's own diagnostic should survive, got %q", err)
	}
}

func TestIntegrationLLDAPWrongPasswordDoesNotLeakIt(t *testing.T) {
	requireIT(t)
	_, err := ldapx.Connect(ctx(t), itLLDAPProfile(t), nil, "definitely-not-the-password")
	if err == nil {
		t.Fatal("a wrong password should not connect")
	}
	if strings.Contains(err.Error(), "definitely-not-the-password") {
		t.Errorf("the password leaked into the error text: %v", err)
	}
}

// lldap advertises no controls at all, so it exercises the no-paging fallback
// against a real server: the result is capped and reported as truncated rather
// than handing back a cookie that would never work.
func TestIntegrationLLDAPHasNoPagingSoResultsTruncate(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itLLDAPProfile(t), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if c.SupportsPaging() {
		t.Skip("this lldap advertises paged results; the fallback is not what runs here")
	}

	page, err := c.Children(ctx(t), "ou=groups,"+itBaseDN, ldapx.PageRequest{Size: 1})
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("asked for 1, got %d", len(page.Entries))
	}
	if !page.Truncated {
		t.Error("the lab lldap has three groups, so one page of one is truncated")
	}
	if page.More() {
		t.Error("a server without paging must not hand back a cookie; there is nothing to continue")
	}
}

// -------------------------------------------------------------- quick search

// A quick search on a standards-compliant server finds people by any of the
// attributes in the generic list.
func TestIntegrationQuickSearch(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itProfile(t, config.SecurityNone), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	find := func(words string) []string {
		t.Helper()
		filter := ldapx.QuickFilter(words, c.Vendor())
		if filter == "" {
			t.Fatalf("%q produced no filter", words)
		}
		page, err := c.Search(ctx(t), ldapx.Query{
			BaseDN: itBaseDN, Scope: ldapx.ScopeSubtree, Filter: filter,
		}, ldapx.PageRequest{Size: 50})
		if err != nil {
			t.Fatalf("%q (%s): %v", words, filter, err)
		}
		var dns []string
		for _, e := range page.Entries {
			dns = append(dns, strings.ToLower(e.DN))
		}
		return dns
	}

	jdoe := "uid=jdoe,ou=people,dc=example,dc=com"

	// By uid, by surname, by given name, by mail — all reach the same person.
	for _, words := range []string{"jdoe", "doe", "john", "jdoe@example"} {
		got := find(words)
		if !containsDN(got, jdoe) {
			t.Errorf("quick search %q found %v, want it to include %s", words, got, jdoe)
		}
	}

	// Two words must narrow, not widen: both have to match the same entry.
	if got := find("john doe"); len(got) != 1 || !containsDN(got, jdoe) {
		t.Errorf(`quick search "john doe" = %v, want only %s`, got, jdoe)
	}
	// Two words that do not share an entry find nothing.
	if got := find("john smith"); len(got) != 0 {
		t.Errorf(`quick search "john smith" = %v, want nothing`, got)
	}
	// A term matching nobody finds nobody, rather than erroring.
	if got := find("zzzznothing"); len(got) != 0 {
		t.Errorf("quick search for a miss = %v, want nothing", got)
	}
}

// The reason the attribute lists are per-vendor: lldap cannot substring-match
// sn or givenName, and rather than erroring it returns nothing and takes the
// whole OR down with it. The generic list would therefore find nobody here,
// while lldap's own list finds them.
func TestIntegrationQuickSearchLLDAPNeedsItsOwnAttributes(t *testing.T) {
	requireIT(t)
	c, err := ldapx.Connect(ctx(t), itLLDAPProfile(t), nil, itAdminPwd)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	if c.Vendor() != ldapx.VendorLLDAP {
		t.Fatalf("vendor = %v, want lldap", c.Vendor())
	}

	search := func(filter string) int {
		t.Helper()
		page, err := c.Search(ctx(t), ldapx.Query{
			BaseDN: itBaseDN, Scope: ldapx.ScopeSubtree, Filter: filter,
		}, ldapx.PageRequest{Size: 50})
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		return len(page.Entries)
	}

	// What PADL actually sends for lldap.
	if n := search(ldapx.QuickFilter("admin", c.Vendor())); n < 1 {
		t.Errorf("lldap quick search for admin found %d entries, want at least one", n)
	}

	// The generic list, which is what a one-size filter would send. If this
	// ever starts matching, lldap has been fixed and the special case can go.
	generic := ldapx.QuickFilterFor([]string{"admin"}, ldapx.QuickSearchAttributes(ldapx.VendorGeneric))
	if n := search(generic); n > 0 {
		t.Logf("lldap now matches the generic filter (%d entries) — recheck whether "+
			"lldapQuickAttributes still needs to be special-cased", n)
	}

	// The precise quirk, pinned so a change in lldap is noticed.
	if n := search("(cn=admin*)"); n != 1 {
		t.Errorf("(cn=admin*) alone = %d entries, want 1", n)
	}
	if n := search("(|(cn=admin*)(sn=admin*))"); n != 0 {
		t.Logf("lldap no longer poisons an OR containing a substring match on sn "+
			"(%d entries); the narrow attribute list may be relaxable", n)
	}
}

func containsDN(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------- Active Directory

// These test Active Directory, which PADL carries more special handling for
// than any other server and could not be run against at all. The lab's domain
// controller happens to be Samba, seeded by dev/samba-seed.sh, because that is
// how a domain fits in a container — what is under test is AD's behaviour.
//
// The administrator's password is not the lab's usual one: AD enforces
// complexity on it at provision time. Everything the seed creates afterwards
// does use it.
const (
	itADBaseDN   = "DC=ad,DC=example,DC=com"
	itADPeopleDN = "OU=People,DC=ad,DC=example,DC=com"
	itADAdminDN  = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
	itADAdminPwd = "Padl-Lab-1"
	itADUserDN   = "CN=John Doe,OU=People,DC=ad,DC=example,DC=com"
)

func itADProfile(t *testing.T, security config.Security) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "it-ad"
	p.Name = "Active Directory lab"
	p.Host = itHost()
	p.Security = security
	p.Bind = config.BindSimple
	p.BindDN = itADAdminDN
	p.PasswordRef = config.PasswordPrompt
	p.BaseDN = itADBaseDN
	p.TimeoutSeconds = 15
	if security == config.SecurityLDAPS {
		p.Port = itPort(t, "PADL_IT_AD_LDAPS_PORT", "13638")
	} else {
		p.Port = itPort(t, "PADL_IT_AD_LDAP_PORT", "13392")
	}
	return p
}

// connectAD does the trust-on-first-use dance the UI does, because the domain
// controller's certificate is self-signed and every AD test needs a connection
// before it can test anything else.
func connectAD(t *testing.T, security config.Security) *ldapx.Client {
	t.Helper()
	p := itADProfile(t, security)

	c, err := ldapx.Connect(ctx(t), p, nil, itADAdminPwd)
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	cte, ok := ldapx.AsCertTrustError(err)
	if !ok {
		t.Fatalf("connect to the AD lab: %v", err)
	}
	pin := cte.Pin()
	c, err = ldapx.Connect(ctx(t), p, &pin, itADAdminPwd)
	if err != nil {
		t.Fatalf("connect to the AD lab with the pin: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A domain controller has to be recognised as one: the vendor decides which
// naming contexts the tree offers and which attributes a quick search covers.
func TestIntegrationADIsDetectedAndBrowsable(t *testing.T) {
	requireIT(t)
	c := connectAD(t, config.SecurityLDAPS)

	if c.Vendor() != ldapx.VendorActiveDirectory {
		t.Fatalf("vendor = %v, want Active Directory", c.Vendor())
	}
	if !c.SupportsPaging() {
		t.Error("Active Directory advertises RFC 2696; PADL should have seen it")
	}

	root := c.Root()
	if root.DefaultNamingContext == "" {
		t.Error("AD publishes defaultNamingContext, which is what the tree opens on")
	}
	if !containsDN(root.Bases(itADBaseDN, false), itADBaseDN) {
		t.Errorf("bases = %v, want the domain naming context", root.Bases(itADBaseDN, false))
	}

	// The domain root's children include the seeded containers. AD answers a
	// one-level search here with referrals to the other naming contexts mixed
	// in, which must not become tree rows or crash the loader.
	page, err := c.Children(ctx(t), itADBaseDN, ldapx.PageRequest{Size: 100})
	if err != nil {
		t.Fatalf("children of %s: %v", itADBaseDN, err)
	}
	var dns []string
	for _, e := range page.Entries {
		dns = append(dns, e.DN)
		if strings.TrimSpace(e.DN) == "" {
			t.Error("a referral was turned into an entry with no DN")
		}
	}
	for _, want := range []string{itADPeopleDN, "OU=Groups," + itADBaseDN} {
		if !containsDN(dns, want) {
			t.Errorf("children of the domain = %v, want %s among them", dns, want)
		}
	}
}

// A domain controller with LDAP signing required refuses a simple bind on an
// unencrypted connection, which is how any hardened AD is configured and what
// the lab DC does. PADL has to report that as the server's own diagnostic
// rather than a generic failure — it is the difference between "use LDAPS" and
// "something went wrong".
func TestIntegrationADRefusesSimpleBindWithoutTLS(t *testing.T) {
	requireIT(t)
	_, err := ldapx.Connect(ctx(t), itADProfile(t, config.SecurityNone), nil, itADAdminPwd)
	if err == nil {
		t.Fatal("a cleartext simple bind should have been refused")
	}
	msg := err.Error()
	if strings.Contains(msg, itADAdminPwd) {
		t.Errorf("the password leaked into the error: %q", msg)
	}
	// Result 8 is strongerAuthRequired. The server's text names the actual
	// problem, so losing it would leave nothing worth reading.
	if !strings.Contains(msg, "LDAP result 8") {
		t.Errorf("error = %q, want the strongerAuthRequired result code", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "encryption") {
		t.Errorf("error = %q, want the server's own diagnostic kept", msg)
	}
}

// The two bind names people actually use on Active Directory, neither of which
// is a DN. PADL used to refuse both before dialling on the grounds that a bind
// name has to parse as a DN, which made the normal way in look like a typo.
func TestIntegrationADAcceptsNonDNBindNames(t *testing.T) {
	requireIT(t)

	// One connect to get the certificate on file, so the bind is what is being
	// tested rather than the trust prompt.
	base := itADProfile(t, config.SecurityLDAPS)
	_, err := ldapx.Connect(ctx(t), base, nil, itADAdminPwd)
	cte, ok := ldapx.AsCertTrustError(err)
	if !ok {
		t.Fatalf("expected the trust prompt on a first connect, got %v", err)
	}
	pin := cte.Pin()

	for _, name := range []string{
		"administrator@ad.example.com", // userPrincipalName
		`AD\Administrator`,             // NetBIOS domain and account
		itADAdminDN,                    // and the DN still works
	} {
		p := base
		p.BindDN = name
		c, err := ldapx.Connect(ctx(t), p, &pin, itADAdminPwd)
		if err != nil {
			t.Errorf("bind as %q: %v", name, err)
			continue
		}
		if _, err := c.Entry(ctx(t), itADUserDN, false); err != nil {
			t.Errorf("bound as %q but could not read: %v", name, err)
		}
		_ = c.Close()
	}

	// A name the server does not know is still an error, just the server's one.
	p := base
	p.BindDN = "nobody@ad.example.com"
	if _, err := ldapx.Connect(ctx(t), p, &pin, itADAdminPwd); err == nil {
		t.Error("an unknown principal should not bind")
	} else if strings.Contains(err.Error(), itADAdminPwd) {
		t.Errorf("the password leaked into the error: %v", err)
	}
}

// StartTLS gets the same trust decision LDAPS does, and is the other way into a
// domain controller that will not take a cleartext bind.
func TestIntegrationADStartTLS(t *testing.T) {
	requireIT(t)
	c := connectAD(t, config.SecurityStartTLS)

	if c.Vendor() != ldapx.VendorActiveDirectory {
		t.Errorf("vendor over StartTLS = %v, want Active Directory", c.Vendor())
	}
	if _, err := c.Children(ctx(t), itADPeopleDN, ldapx.PageRequest{Size: 10}); err != nil {
		t.Fatalf("search over StartTLS: %v", err)
	}
}

// The attributes PADL renders rather than prints. Every one of these is
// AD-shaped and none of them could be checked against a live server before.
func TestIntegrationADRendersItsOwnAttributes(t *testing.T) {
	requireIT(t)
	c := connectAD(t, config.SecurityLDAPS)

	e, err := c.Entry(ctx(t), itADUserDN, false)
	if err != nil {
		t.Fatalf("read %s: %v", itADUserDN, err)
	}

	value := func(attr string) ldapx.Value {
		t.Helper()
		for _, a := range e.Attributes {
			if strings.EqualFold(a.Name, attr) {
				return ldapx.FormatAll(a)[0]
			}
		}
		t.Fatalf("%s has no %s", e.DN, attr)
		return ldapx.Value{}
	}

	// A SID off the wire is a packed little-endian structure; S-1-5-21-… is the
	// only form anyone can compare against what a Windows tool shows.
	if sid := value("objectSid"); !strings.HasPrefix(sid.Text, "S-1-5-21-") {
		t.Errorf("objectSid = %q, want the S-1-5-21-… form", sid.Text)
	} else if !sid.Binary {
		t.Error("a rendered SID is still a binary value; the UI offers a hex dump for it")
	}

	// The first three fields of a GUID are little-endian on the wire. A plain
	// hex dump with dashes in it would look right and be wrong.
	guid := value("objectGUID")
	if len(guid.Text) != 36 || strings.Count(guid.Text, "-") != 4 {
		t.Errorf("objectGUID = %q, want a formatted UUID", guid.Text)
	}
	if len(guid.Raw) != 16 {
		t.Errorf("objectGUID raw length = %d, want 16", len(guid.Raw))
	}

	// 512 is NORMAL_ACCOUNT. The number alone tells nobody anything.
	if uac := value("userAccountControl"); !strings.Contains(uac.Text, "NORMAL_ACCOUNT") {
		t.Errorf("userAccountControl = %q, want the flag named", uac.Text)
	}

	// pwdLastSet is a FILETIME: 100ns ticks since 1601, which is an eighteen
	// digit number until something renders it.
	pwd := value("pwdLastSet")
	if strings.HasPrefix(pwd.Text, "1") && len(pwd.Text) > 15 {
		t.Errorf("pwdLastSet = %q, want a rendered timestamp", pwd.Text)
	}
	if !strings.Contains(pwd.Text, "20") {
		t.Errorf("pwdLastSet = %q, want a date in it", pwd.Text)
	}

	// whenCreated is generalizedTime, the other AD timestamp spelling.
	if created := value("whenCreated"); strings.HasSuffix(created.Text, "Z") {
		t.Errorf("whenCreated = %q, want it rendered rather than passed through", created.Text)
	}

	// The seed puts two addresses on proxyAddresses because AD's mail is
	// single-valued, so the object pane has a multi-valued attribute to draw.
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, "proxyAddresses") && len(a.Values) != 2 {
			t.Errorf("proxyAddresses has %d values, want 2", len(a.Values))
		}
	}
}

// The domain object carries the password policy, which AD stores as negative
// FILETIME intervals, and the group carries the flag word that decides what
// kind of group it is. Both are numbers nobody reads.
func TestIntegrationADRendersPolicyAndGroupFlags(t *testing.T) {
	requireIT(t)
	c := connectAD(t, config.SecurityLDAPS)

	first := func(dn, attr string) string {
		t.Helper()
		e, err := c.Entry(ctx(t), dn, false)
		if err != nil {
			t.Fatalf("read %s: %v", dn, err)
		}
		for _, a := range e.Attributes {
			if strings.EqualFold(a.Name, attr) {
				return ldapx.FormatAll(a)[0].Text
			}
		}
		t.Fatalf("%s has no %s", dn, attr)
		return ""
	}

	// The lab domain: passwords never expire, minimum age a day, lockout
	// window half an hour.
	if got := first(itADBaseDN, "maxPwdAge"); got != "never" {
		t.Errorf("maxPwdAge = %q, want never", got)
	}
	if got := first(itADBaseDN, "minPwdAge"); got != "1 day" {
		t.Errorf("minPwdAge = %q, want 1 day", got)
	}
	if got := first(itADBaseDN, "lockoutDuration"); !strings.Contains(got, "minute") &&
		!strings.Contains(got, "not set") {
		t.Errorf("lockoutDuration = %q, want a duration", got)
	}
	// instanceType 5 on a naming context head, and the functional level named.
	if got := first(itADBaseDN, "instanceType"); !strings.Contains(got, "NC_HEAD") {
		t.Errorf("instanceType = %q, want NC_HEAD named", got)
	}
	if got := first(itADBaseDN, "msDS-Behavior-Version"); !strings.Contains(got, "Windows Server") {
		t.Errorf("msDS-Behavior-Version = %q, want the level named", got)
	}
	// systemFlags arrives negative, which is the case a uint parse would miss.
	if got := first(itADBaseDN, "systemFlags"); !strings.Contains(got, "DISALLOW_DELETE") {
		t.Errorf("systemFlags = %q, want the flags named", got)
	}

	group := "CN=engineers,OU=Groups," + itADBaseDN
	if got := first(group, "groupType"); !strings.Contains(got, "SECURITY_ENABLED") ||
		!strings.Contains(got, "GLOBAL") {
		t.Errorf("groupType = %q, want a global security group", got)
	}
	if got := first(group, "sAMAccountType"); !strings.Contains(got, "SAM_GROUP_OBJECT") {
		t.Errorf("sAMAccountType = %q, want it named", got)
	}
	if got := first(itADUserDN, "sAMAccountType"); !strings.Contains(got, "SAM_USER_OBJECT") {
		t.Errorf("user sAMAccountType = %q, want it named", got)
	}
	if got := first(itADUserDN, "primaryGroupID"); !strings.Contains(got, "Domain Users") {
		t.Errorf("primaryGroupID = %q, want the well-known group named", got)
	}
}

// A quick search on AD leads with sAMAccountName, and matches it as typed
// rather than by prefix. Both halves are worth proving against a real server:
// the attribute list because AD is the least forgiving of a name it does not
// know, and the exact match because it is the one that has to still find people.
func TestIntegrationADQuickSearch(t *testing.T) {
	requireIT(t)
	c := connectAD(t, config.SecurityLDAPS)

	find := func(words string) []string {
		t.Helper()
		filter := ldapx.QuickFilter(words, c.Vendor())
		if filter == "" {
			t.Fatalf("%q produced no filter", words)
		}
		page, err := c.Search(ctx(t), ldapx.Query{
			BaseDN: itADBaseDN, Scope: ldapx.ScopeSubtree, Filter: filter,
		}, ldapx.PageRequest{Size: 50})
		if err != nil {
			t.Fatalf("%q (%s): %v", words, filter, err)
		}
		var dns []string
		for _, e := range page.Entries {
			dns = append(dns, e.DN)
		}
		return dns
	}

	// The login name, matched exactly, is the search people actually type.
	if dns := find("jdoe"); !containsDN(dns, itADUserDN) {
		t.Errorf("quick search for jdoe = %v, want John Doe", dns)
	}
	// A prefix of the display name still works, through cn and displayName.
	if dns := find("john"); !containsDN(dns, itADUserDN) {
		t.Errorf("quick search for john = %v, want John Doe", dns)
	}
	// Two words narrow rather than widen.
	if dns := find("john doe"); !containsDN(dns, itADUserDN) {
		t.Errorf("quick search for john doe = %v, want John Doe", dns)
	}
	// The whole AD attribute list has to be something the server will accept.
	// RFC 4511 says an unknown attribute makes the filter Undefined, and AD is
	// the server most likely to hold PADL to it.
	if dns := find("alice"); !containsDN(dns, "CN=Alice Smith,"+itADPeopleDN) {
		t.Errorf("quick search for alice = %v, want Alice Smith", dns)
	}

	// A lone short word is matched as typed, so it finds nothing rather than
	// dragging the whole domain back one page at a time.
	if filter := ldapx.QuickFilter("a", c.Vendor()); strings.Contains(filter, "*") {
		t.Errorf("a single short word should not be wildcarded: %s", filter)
	}
}

// AD is the server the paging code exists for. A page size of one walks the
// seeded people one at a time, which is the loop the tree runs when a container
// has more children than the page size.
func TestIntegrationADPagedChildren(t *testing.T) {
	requireIT(t)
	c := connectAD(t, config.SecurityLDAPS)

	seen := map[string]bool{}
	req := ldapx.PageRequest{Size: 1}
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("paging did not terminate")
		}
		page, err := c.Children(ctx(t), itADPeopleDN, req)
		if err != nil {
			t.Fatalf("children page %d: %v", pages, err)
		}
		for _, e := range page.Entries {
			if seen[strings.ToLower(e.DN)] {
				t.Errorf("%s came back on more than one page", e.DN)
			}
			seen[strings.ToLower(e.DN)] = true
		}
		if !page.More() {
			break
		}
		req = page.Next(1)
	}

	for _, want := range []string{itADUserDN, "CN=Alice Smith," + itADPeopleDN} {
		if !seen[strings.ToLower(want)] {
			t.Errorf("paging missed %s; saw %v", want, keysOf(seen))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
