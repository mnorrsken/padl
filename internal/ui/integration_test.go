package ui

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/mnorrsken/padl/internal/config"
)

// This drives the whole stack — real UI, real go-ldap, real TLS handshake —
// against the throwaway server in dev/docker-compose.yml. It is the only test
// that proves the trust prompt, the pin, and the tree all line up end to end.
//
//	docker compose -f dev/docker-compose.yml up -d
//	PADL_IT=1 go test ./internal/ui/ -run Integration -v

func labProfile(t *testing.T, security config.Security, port string) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "lab"
	p.Name = "Lab"
	p.Host = envOr("PADL_IT_HOST", "127.0.0.1")
	p.Security = security
	p.Bind = config.BindSimple
	p.BindDN = "cn=admin,dc=example,dc=com"
	p.PasswordRef = config.PasswordEnv
	p.TimeoutSeconds = 10

	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("bad port %q: %v", port, err)
	}
	p.Port = n
	return p
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireIT(t *testing.T) {
	t.Helper()
	if os.Getenv("PADL_IT") != "1" {
		t.Skip("set PADL_IT=1 and start dev/docker-compose.yml to run integration tests")
	}
}

// TestIntegrationLDAPSPromptPinAndBrowse walks the whole first-run story: an
// untrusted certificate, the prompt, the pin, the retry, and a real tree.
func TestIntegrationLDAPSPromptPinAndBrowse(t *testing.T) {
	requireIT(t)

	p := labProfile(t, config.SecurityLDAPS, envOr("PADL_IT_LDAPS_PORT", "13636"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	// nil Connect means the real ldapx.Connect.
	h := start(t, p, nil, config.NewSecrets())

	h.waitFor("Untrusted certificate", "SHA-256")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)

	h.waitFor("dc=example,dc=com", "ou=Groups", "ou=People", "OpenLDAP")

	pin, ok := h.trust.Get(p.ID)
	if !ok {
		t.Fatal("accepting the prompt should have pinned the certificate")
	}
	if !strings.Contains(pin.Fingerprint, ":") {
		t.Errorf("pinned fingerprint looks wrong: %q", pin.Fingerprint)
	}

	// Walk into ou=People and read a real entry.
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.waitFor("dn: ou=People,dc=example,dc=com")
	h.key(tcell.KeyRight)
	h.waitFor("uid=asmith", "uid=jdoe")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com", "John Doe", "jdoe@example.com")

	// Operational attributes come from the server, not from a fixture.
	h.key(tcell.KeyTab)
	h.rune('o')
	h.waitFor("createTimestamp", "entryUUID")
}

// A second run with the pin already on file must connect straight through.
func TestIntegrationPinnedCertConnectsWithoutPrompting(t *testing.T) {
	requireIT(t)

	p := labProfile(t, config.SecurityLDAPS, envOr("PADL_IT_LDAPS_PORT", "13636"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	// First run: accept the certificate and keep what got pinned.
	first := start(t, p, nil, config.NewSecrets())
	first.waitFor("Untrusted certificate")
	first.key(tcell.KeyTab)
	first.key(tcell.KeyEnter)
	first.waitFor("ou=People")

	pin, ok := first.trust.Get(p.ID)
	if !ok {
		t.Fatal("expected a pin after accepting the prompt")
	}

	// Second run, starting from that pin: no prompt, straight to the tree.
	second := start(t, p, nil, config.NewSecrets(), func(ts *config.TrustStore) {
		if err := ts.Set(p.ID, pin); err != nil {
			t.Fatalf("seed pin: %v", err)
		}
	})
	second.waitFor("dc=example,dc=com", "ou=People")
	if strings.Contains(second.text(), "Untrusted certificate") {
		t.Error("a pinned certificate should not prompt again")
	}
}

func TestIntegrationStartTLSBrowse(t *testing.T) {
	requireIT(t)

	p := labProfile(t, config.SecurityStartTLS, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("Untrusted certificate")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("dc=example,dc=com", "ou=People")
}

func TestIntegrationBadPasswordShowsAResultCode(t *testing.T) {
	requireIT(t)

	p := labProfile(t, config.SecurityNone, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "definitely-not-the-password")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("bind as cn=admin,dc=example,dc=com failed", "LDAP result 49")

	if strings.Contains(h.text(), "definitely-not-the-password") {
		t.Error("the password must never reach the status bar")
	}
}

// ---------------------------------------------------------------------- lldap

func lldapProfile(t *testing.T) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "lldap"
	p.Name = "lldap"
	p.Host = envOr("PADL_IT_HOST", "127.0.0.1")
	p.Security = config.SecurityNone
	p.Bind = config.BindSimple
	p.BindDN = "uid=admin,ou=people,dc=example,dc=com"
	p.PasswordRef = config.PasswordEnv
	p.TimeoutSeconds = 10

	n, err := strconv.Atoi(envOr("PADL_IT_LLDAP_PORT", "13390"))
	if err != nil {
		t.Fatalf("bad port: %v", err)
	}
	p.Port = n
	return p
}

// lldap answers a one-level search at the tree root with the whole subtree, so
// taking the result at face value gives a flat tree with ou=people and
// ou=groups missing entirely. The containers have to come back.
func TestIntegrationLLDAPTreeShowsTheRealContainers(t *testing.T) {
	requireIT(t)
	p := lldapProfile(t)
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("dc=example,dc=com", "ou=people", "ou=groups", "lldap")

	screen := h.text()
	// The users and groups belong under their containers, not at the top level.
	root := strings.Index(screen, "dc=example,dc=com")
	people := strings.Index(screen, "ou=people")
	if root < 0 || people < 0 {
		t.Fatalf("tree is missing its containers:\n%s", screen)
	}
	if strings.Contains(screen, "uid=admin") {
		t.Errorf("uid=admin is a grandchild of the root and must not be listed under it:\n%s", screen)
	}

	// Expanding ou=people does a correct one-level search and finds the user.
	h.key(tcell.KeyDown) // ou=groups
	h.key(tcell.KeyDown) // ou=people
	h.waitFor("dn: ou=people,dc=example,dc=com")
	h.key(tcell.KeyRight)
	h.waitFor("uid=admin")

	h.key(tcell.KeyDown)
	h.waitFor("dn: uid=admin,ou=people,dc=example,dc=com", "inetOrgPerson")
}

// The root has no readable entry on lldap. Showing a different entry's
// attributes under its heading would be worse than saying nothing.
func TestIntegrationLLDAPRootReportsRatherThanShowingTheWrongEntry(t *testing.T) {
	requireIT(t)
	p := lldapProfile(t)
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("could not read dc=example,dc=com")

	if strings.Contains(h.text(), "dn: uid=admin") {
		t.Error("the object pane must not show another entry under the root's heading")
	}
}

// The failure the user hits first, seen through the UI: the dialog has to carry
// the server's explanation, not just a result code.
func TestIntegrationLLDAPWrongBindDNShowsTheServerExplanation(t *testing.T) {
	requireIT(t)
	p := lldapProfile(t)
	p.BindDN = "cn=admin,dc=example,dc=com"
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("Connect failed", "LDAP result 64", "uid=id,ou=people")
}

// ------------------------------------------------------------- DN links

// The lab's engineers group has real member DNs, so this walks the link from a
// group to one of its members against a live server, expanding ou=People on the
// way because the jump has to open it.
func TestIntegrationFollowMemberDN(t *testing.T) {
	requireIT(t)
	p := labProfile(t, config.SecurityNone, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=Groups", "ou=People")

	h.key(tcell.KeyDown) // ou=Groups
	h.key(tcell.KeyRight)
	h.waitFor("cn=engineers")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=engineers,ou=Groups,dc=example,dc=com", "(enter to follow)")

	h.key(tcell.KeyTab)
	h.selectValueRow("uid=jdoe,ou=People,dc=example,dc=com  (enter to follow)")
	h.key(tcell.KeyEnter)

	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com", "John Doe")
	if !h.rowHighlighted("[u] uid=jdoe", 2*time.Second) {
		t.Errorf("the jump target should be selected in the tree:\n%s", h.text())
	}
}

// On lldap the tree's containers are inferred rather than read, so a jump has
// to walk through a synthesised node to reach a real one.
func TestIntegrationLLDAPFollowDNThroughASynthesizedContainer(t *testing.T) {
	requireIT(t)
	p := lldapProfile(t)
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=groups", "ou=people")

	h.key(tcell.KeyDown) // ou=groups
	h.key(tcell.KeyRight)
	h.waitFor("cn=lldap_admin")
	h.key(tcell.KeyDown)
	h.waitFor("dn: cn=lldap_admin,ou=groups,dc=example,dc=com", "(enter to follow)")

	h.key(tcell.KeyTab)
	h.selectValueRow("uid=admin,ou=people,dc=example,dc=com  (enter to follow)")
	h.key(tcell.KeyEnter)

	h.waitFor("dn: uid=admin,ou=people,dc=example,dc=com")
	if !h.rowHighlighted("[u] uid=admin", 2*time.Second) {
		t.Errorf("the jump should reach the user through the inferred container:\n%s", h.text())
	}
}

// ------------------------------------------------------- search and export

func TestIntegrationSearchAndJump(t *testing.T) {
	requireIT(t)
	p := labProfile(t, config.SecurityNone, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=People", "ou=Groups")

	h.rune('/')
	h.waitFor("scope sub", "under dc=example,dc=com")
	h.typeString("(uid=asmith)")
	h.key(tcell.KeyEnter)

	h.waitFor("1 for (uid=asmith)", "uid=asmith,ou=People,dc=example,dc=com")
	h.waitFor("dn: uid=asmith,ou=People,dc=example,dc=com", "Alice Smith")

	h.key(tcell.KeyEnter)
	h.waitFor("[u] uid=asmith")
	if !h.rowHighlighted("[u] uid=asmith", 2*time.Second) {
		t.Errorf("the chosen result should be selected in the tree:\n%s", h.text())
	}
}

// A filter the server rejects must surface the server's own complaint.
func TestIntegrationBadFilterIsReported(t *testing.T) {
	requireIT(t)
	p := labProfile(t, config.SecurityNone, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=People")

	h.rune('/')
	h.typeString("(uid=")
	h.key(tcell.KeyEnter)
	h.waitFor("Search failed")
}

// Export against a real server, then check the file is LDIF a real tool would
// accept: a version header, one record per entry, and the values intact.
func TestIntegrationExportSubtree(t *testing.T) {
	requireIT(t)
	p := labProfile(t, config.SecurityNone, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=People")

	out := filepath.Join(t.TempDir(), "people.ldif")

	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown) // ou=People
	h.waitFor("dn: ou=People,dc=example,dc=com")
	h.rune('E')
	h.waitFor("Export subtree to LDIF")
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
	for _, want := range []string{
		"version: 1",
		"dn: ou=People,dc=example,dc=com",
		"dn: uid=jdoe,ou=People,dc=example,dc=com",
		"dn: uid=asmith,ou=People,dc=example,dc=com",
		"mail: jdoe@example.com",
		"mail: john.doe@example.com",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("export is missing %q:\n%s", want, text)
		}
	}
	// No line may exceed the fold width, or the file is not conformant.
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 76 {
			t.Errorf("line exceeds 76 columns: %q", line)
		}
	}
}

// Quick search end to end against a real server: bare words in, the right
// person out.
func TestIntegrationQuickSearchThroughTheUI(t *testing.T) {
	requireIT(t)
	p := labProfile(t, config.SecurityNone, envOr("PADL_IT_LDAP_PORT", "13389"))
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=People", "OpenLDAP")

	h.rune('/')
	h.waitFor("cn sn givenName displayName uid mail ou o description")
	h.typeString("john doe")
	h.waitFor("all 2 words, each in any of")
	h.key(tcell.KeyEnter)

	h.waitFor("1 for john doe", "uid=jdoe,ou=People,dc=example,dc=com")
	h.waitFor("dn: uid=jdoe,ou=People,dc=example,dc=com", "John Doe")
}

// On lldap the bar has to offer lldap's own attribute list, not the generic
// one, or the search finds nothing.
func TestIntegrationQuickSearchUsesTheVendorsAttributes(t *testing.T) {
	requireIT(t)
	p := lldapProfile(t)
	t.Setenv(config.EnvVar(p.ID), "padl-lab")

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("ou=people", "lldap")

	h.rune('/')
	h.waitFor("uid cn mail displayName")
	if strings.Contains(h.text(), "givenName") {
		t.Errorf("lldap cannot substring-match givenName; it must not be offered:\n%s", h.text())
	}

	h.typeString("admin")
	h.key(tcell.KeyEnter)
	h.waitFor("for admin", "uid=admin,ou=people,dc=example,dc=com")
}
