package ldapx_test

import (
	"context"
	"errors"
	"os"
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

	children, truncated, err := c.Children(ctx(t), itBaseDN, 100)
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if truncated {
		t.Error("the seed tree is small; nothing should be truncated")
	}
	rdns := map[string]bool{}
	for _, e := range children {
		rdns[e.RDN()] = true
	}
	for _, want := range []string{"ou=People", "ou=Groups"} {
		if !rdns[want] {
			t.Errorf("children of %s = %v, want it to include %s", itBaseDN, rdns, want)
		}
	}

	// A truncating limit must both cut the list and say that it did.
	short, truncated, err := c.Children(ctx(t), "ou=People,"+itBaseDN, 1)
	if err != nil {
		t.Fatalf("children with limit: %v", err)
	}
	if len(short) != 1 || !truncated {
		t.Errorf("limit 1 gave %d entries, truncated=%v", len(short), truncated)
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

	if _, _, err := c.Children(ctx(t), itBaseDN, 10); err != nil {
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

	if _, _, err := c.Children(ctx(t), itBaseDN, 10); err != nil {
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
	if _, _, err := c.Children(cancelled, itBaseDN, 100); !errors.Is(err, context.Canceled) {
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

	children, _, err := c.Children(ctx(t), itBaseDN, 100)
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	rdns := map[string]bool{}
	for _, e := range children {
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

// A bare username never reaches the server: PADL says what a DN looks like.
func TestIntegrationLLDAPBareUsernameIsCaughtLocally(t *testing.T) {
	requireIT(t)
	p := itLLDAPProfile(t)
	p.BindDN = "admin"

	_, err := ldapx.Connect(ctx(t), p, nil, itAdminPwd)
	if err == nil {
		t.Fatal("a bare username is not a bind DN")
	}
	if !strings.Contains(err.Error(), "is not a distinguished name") {
		t.Errorf("the message should name the mistake, got %q", err)
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
