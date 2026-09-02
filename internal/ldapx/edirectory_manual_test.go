package ldapx_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ldapx"
)

// Manual tests against a real eDirectory server.
//
// They are not part of `make it`: eDirectory cannot be brought up from a public
// image, so there is nothing for CI to run them against. Point them at your own
// server instead — see docs/manual-tests.md.
//
//	PADL_EDIR=1 \
//	PADL_EDIR_BIND_DN='cn=admin,o=example' \
//	PADL_EDIR_PASSWORD='...' \
//	PADL_EDIR_BASE_DN='o=example' \
//	go test ./internal/ldapx/ -run EDir -v
//
// What they are for: eDirectory is the one vendor PADL has special handling for
// that no lab container covers, so its quirks were written from the
// documentation and left unproven. These turn that into something checkable.

func requireEDir(t *testing.T) {
	t.Helper()
	if os.Getenv("PADL_EDIR") != "1" {
		t.Skip("set PADL_EDIR=1 and the PADL_EDIR_* variables to run the eDirectory manual tests")
	}
	for _, key := range []string{"PADL_EDIR_BIND_DN", "PADL_EDIR_PASSWORD", "PADL_EDIR_BASE_DN"} {
		if os.Getenv(key) == "" {
			t.Fatalf("%s must be set; see docs/manual-tests.md", key)
		}
	}
}

func edirEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func edirPassword() string { return os.Getenv("PADL_EDIR_PASSWORD") }
func edirBaseDN() string   { return os.Getenv("PADL_EDIR_BASE_DN") }

func edirProfile(t *testing.T, security config.Security) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "edir"
	p.Name = "eDirectory"
	p.Host = edirEnv("PADL_EDIR_HOST", "127.0.0.1")
	p.Security = security
	p.Bind = config.BindSimple
	p.BindDN = os.Getenv("PADL_EDIR_BIND_DN")
	p.PasswordRef = config.PasswordPrompt
	p.BaseDN = edirBaseDN()
	p.TimeoutSeconds = 30

	portVar, fallback := "PADL_EDIR_LDAP_PORT", "389"
	if security == config.SecurityLDAPS {
		portVar, fallback = "PADL_EDIR_LDAPS_PORT", "636"
	}
	n, err := strconv.Atoi(edirEnv(portVar, fallback))
	if err != nil {
		t.Fatalf("bad %s: %v", portVar, err)
	}
	p.Port = n
	return p
}

func edirCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

// connectEDir opens a TLS connection, accepting the certificate the way the UI
// would after the operator approves the trust prompt.
func connectEDir(t *testing.T, security config.Security) *ldapx.Client {
	t.Helper()
	p := edirProfile(t, security)

	c, err := ldapx.Connect(edirCtx(t), p, nil, edirPassword())
	if err == nil {
		return c
	}
	cte, ok := ldapx.AsCertTrustError(err)
	if !ok {
		t.Fatalf("connect: %v", err)
	}
	pin := cte.Pin()
	c, err = ldapx.Connect(edirCtx(t), p, &pin, edirPassword())
	if err != nil {
		t.Fatalf("connect with the pinned certificate: %v", err)
	}
	return c
}

func TestEDirVendorDetection(t *testing.T) {
	requireEDir(t)
	c := connectEDir(t, config.SecurityLDAPS)
	defer c.Close()

	if got := c.Vendor(); got != ldapx.VendorEDirectory {
		t.Errorf("vendor = %v, want eDirectory", got)
	}
	root := c.Root()
	if !strings.Contains(strings.ToLower(root.VendorVersion), "edirectory") {
		t.Errorf("vendorVersion = %q, want it to name eDirectory", root.VendorVersion)
	}
	if root.DSAName == "" {
		t.Error("eDirectory publishes dsaName; PADL asks for it and should see it")
	}
	t.Logf("vendorName=%q vendorVersion=%q dsaName=%q",
		root.VendorName, root.VendorVersion, root.DSAName)
}

// The reason a profile has a base DN override at all.
//
// eDirectory publishes an empty namingContexts, so a tree built only from the
// root DSE would have no roots at all and PADL would show an empty pane. The
// override is what makes the server usable.
func TestEDirPublishesNoNamingContexts(t *testing.T) {
	requireEDir(t)
	c := connectEDir(t, config.SecurityLDAPS)
	defer c.Close()

	root, err := c.RootDSE(edirCtx(t))
	if err != nil {
		t.Fatalf("root DSE: %v", err)
	}

	if discovered := root.Bases("", false); len(discovered) != 0 {
		t.Logf("this server does publish namingContexts (%v) — the override is not "+
			"needed here, but PADL still has to cope with servers that do not", discovered)
	}

	// With the override, the tree has a root to start from.
	base := edirBaseDN()
	got := root.Bases(base, false)
	if len(got) != 1 || !ldapx.EqualDN(got[0], base) {
		t.Fatalf("Bases(%q) = %v, want exactly that base", base, got)
	}
}

// eDirectory refuses a simple bind on the plain port with "Confidentiality
// required". PADL must pass that through legibly rather than reducing it to a
// bare code, since the fix — use LDAPS or StartTLS — is in the message.
func TestEDirRefusesSimpleBindWithoutTLS(t *testing.T) {
	requireEDir(t)

	p := edirProfile(t, config.SecurityNone)
	_, err := ldapx.Connect(edirCtx(t), p, nil, edirPassword())
	if err == nil {
		t.Skip("this server allows a simple bind in the clear; nothing to check")
	}
	msg := err.Error()
	if strings.Contains(msg, edirPassword()) {
		t.Fatalf("the password leaked into the error: %v", err)
	}
	if !strings.Contains(msg, "LDAP result 13") {
		t.Errorf("want result 13 (confidentiality required), got: %v", err)
	}
	t.Logf("plain-LDAP bind refused as: %v", err)
}

func TestEDirStartTLSAndLDAPS(t *testing.T) {
	requireEDir(t)

	for _, security := range []config.Security{config.SecurityStartTLS, config.SecurityLDAPS} {
		t.Run(string(security), func(t *testing.T) {
			p := edirProfile(t, security)

			// A first connect with nothing pinned must ask about the
			// certificate, which eDirectory self-signs by default.
			_, err := ldapx.Connect(edirCtx(t), p, nil, edirPassword())
			cte, ok := ldapx.AsCertTrustError(err)
			if !ok {
				if err != nil {
					t.Fatalf("connect: %v", err)
				}
				t.Skip("this server's certificate verifies against the system roots")
			}
			if cte.Fingerprint == "" {
				t.Error("the trust prompt needs a fingerprint to show")
			}

			pin := cte.Pin()
			c, err := ldapx.Connect(edirCtx(t), p, &pin, edirPassword())
			if err != nil {
				t.Fatalf("connect with the pin: %v", err)
			}
			defer c.Close()

			if _, err := c.Entry(edirCtx(t), edirBaseDN(), false); err != nil {
				t.Errorf("read the base entry: %v", err)
			}
		})
	}
}

// eDirectory answers with subordinateCount rather than hasSubordinates or
// numSubordinates. PADL reads all three; this proves the eDirectory spelling is
// the one that arrives, so the tree knows which nodes can be opened.
func TestEDirUsesSubordinateCount(t *testing.T) {
	requireEDir(t)
	c := connectEDir(t, config.SecurityLDAPS)
	defer c.Close()

	page, err := c.Children(edirCtx(t), edirBaseDN(), ldapx.PageRequest{Size: 200})
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if len(page.Entries) == 0 {
		t.Fatalf("no children under %s; the base DN may be wrong", edirBaseDN())
	}

	base, err := c.Entry(edirCtx(t), edirBaseDN(), true)
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	if got := base.First("subordinateCount"); got == "" {
		t.Errorf("no subordinateCount on %s; PADL's eDirectory child hint would not work", edirBaseDN())
	} else {
		t.Logf("subordinateCount=%s, %d children listed", got, len(page.Entries))
	}
}

// The eDirectory quick-search attribute list has to find something. Unlike
// lldap, eDirectory tolerates attributes it does not know inside an OR, so the
// broad list is safe here — this is what proves it.
func TestEDirQuickSearch(t *testing.T) {
	requireEDir(t)
	c := connectEDir(t, config.SecurityLDAPS)
	defer c.Close()

	// Take a real entry from the tree and search for a prefix of its RDN value.
	page, err := c.Children(edirCtx(t), edirBaseDN(), ldapx.PageRequest{Size: 50})
	if err != nil || len(page.Entries) == 0 {
		t.Fatalf("children of %s: %v", edirBaseDN(), err)
	}
	rdn := page.Entries[0].RDN()
	value := rdn
	if i := strings.Index(rdn, "="); i >= 0 {
		value = rdn[i+1:]
	}
	if len(value) > 3 {
		value = value[:3]
	}

	filter := ldapx.QuickFilter(value, ldapx.VendorEDirectory)
	t.Logf("quick search %q -> %s", value, filter)

	hits, err := c.Search(edirCtx(t), ldapx.Query{
		BaseDN: edirBaseDN(), Scope: ldapx.ScopeSubtree, Filter: filter,
	}, ldapx.PageRequest{Size: 50})
	if err != nil {
		t.Fatalf("quick search: %v", err)
	}
	if len(hits.Entries) == 0 {
		t.Errorf("the eDirectory attribute list found nothing for %q; on a server that "+
			"cannot substring-match one of them it may need narrowing, the way lldap did", value)
	}

	// The same search with one attribute alone, to tell "nothing matches" apart
	// from "one attribute poisoned the OR".
	single, err := c.Search(edirCtx(t), ldapx.Query{
		BaseDN: edirBaseDN(), Scope: ldapx.ScopeSubtree, Filter: "(cn=" + value + "*)",
	}, ldapx.PageRequest{Size: 50})
	if err != nil {
		t.Fatalf("single-attribute search: %v", err)
	}
	if len(single.Entries) > 0 && len(hits.Entries) == 0 {
		t.Errorf("(cn=%s*) alone matched %d entries but the full list matched none — "+
			"an attribute in the eDirectory list is poisoning the OR",
			value, len(single.Entries))
	}
}

func TestEDirPaging(t *testing.T) {
	requireEDir(t)
	c := connectEDir(t, config.SecurityLDAPS)
	defer c.Close()

	if !c.SupportsPaging() {
		t.Skip("this server does not advertise RFC 2696")
	}

	seen := map[string]int{}
	req := ldapx.PageRequest{Size: 2}
	pages := 0
	for {
		page, err := c.Children(edirCtx(t), edirBaseDN(), req)
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
		if pages > 100 {
			t.Fatal("paging did not terminate")
		}
		req = page.Next(2)
	}

	for dn, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times across pages, want once", dn, n)
		}
	}
	t.Logf("%d entries over %d pages", len(seen), pages)
}
