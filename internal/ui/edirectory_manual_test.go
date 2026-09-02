package ui

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/mnorrsken/padl/internal/config"
)

// Manual tests driving the whole UI against a real eDirectory server.
//
// Not part of `make it`: there is no public eDirectory image, so CI has nothing
// to run them against. Point them at your own server — see docs/manual-tests.md.
//
//	PADL_EDIR=1 \
//	PADL_EDIR_BIND_DN='cn=admin,o=example' \
//	PADL_EDIR_PASSWORD='...' \
//	PADL_EDIR_BASE_DN='o=example' \
//	go test ./internal/ui/ -run EDir -v

func requireEDirUI(t *testing.T) {
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

func edirUIProfile(t *testing.T, security config.Security, baseDN string) config.Profile {
	t.Helper()
	p := config.NewProfile()
	p.ID = "edir"
	p.Name = "eDirectory"
	p.Host = envOr("PADL_EDIR_HOST", "127.0.0.1")
	p.Security = security
	p.Bind = config.BindSimple
	p.BindDN = os.Getenv("PADL_EDIR_BIND_DN")
	p.PasswordRef = config.PasswordEnv
	p.BaseDN = baseDN
	p.TimeoutSeconds = 30

	portVar, fallback := "PADL_EDIR_LDAP_PORT", "389"
	if security == config.SecurityLDAPS {
		portVar, fallback = "PADL_EDIR_LDAPS_PORT", "636"
	}
	n, err := strconv.Atoi(envOr(portVar, fallback))
	if err != nil {
		t.Fatalf("bad %s: %v", portVar, err)
	}
	p.Port = n
	return p
}

// acceptCertificate clears the trust prompt if one appears. eDirectory
// self-signs its LDAPS certificate, so a first connect normally asks.
func acceptCertificate(h *harness) {
	if !strings.Contains(h.text(), "Untrusted certificate") {
		return
	}
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
}

// The whole point of the base DN override: eDirectory publishes an empty
// namingContexts, so without one the tree has no roots and PADL has to say what
// to do about it rather than showing an empty pane.
func TestEDirWithoutABaseDNSaysWhatToDo(t *testing.T) {
	requireEDirUI(t)

	p := edirUIProfile(t, config.SecurityLDAPS, "") // deliberately no override
	t.Setenv(config.EnvVar(p.ID), os.Getenv("PADL_EDIR_PASSWORD"))

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("Untrusted certificate")
	acceptCertificate(h)
	h.waitConnected()

	if strings.Contains(h.text(), "no naming contexts") {
		h.waitFor("set a base DN")
		return
	}
	t.Log("this server does publish namingContexts, so the tree filled itself in; " +
		"the override is for the ones that do not")
}

func TestEDirBrowseWithABaseDN(t *testing.T) {
	requireEDirUI(t)

	base := os.Getenv("PADL_EDIR_BASE_DN")
	p := edirUIProfile(t, config.SecurityLDAPS, base)
	t.Setenv(config.EnvVar(p.ID), os.Getenv("PADL_EDIR_PASSWORD"))

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("Untrusted certificate", "SHA-256")
	acceptCertificate(h)
	h.waitConnected()

	// The tree roots at the override and opens it, and the header names the
	// vendor PADL detected.
	h.waitFor(base, "eDirectory")

	// The base entry loads in the object pane.
	h.waitFor("dn: " + base)

	// Moving down loads a child, which proves the one-level listing worked.
	h.key(tcell.KeyDown)
	h.waitUntil("a child entry to load", func() bool {
		text := h.text()
		return strings.Contains(text, "dn: ") && !strings.Contains(text, "dn: "+base+" ")
	})
}

// A connect on the plain port must report eDirectory's own explanation, since
// the fix — use LDAPS or StartTLS — is in it.
func TestEDirPlainBindIsReportedLegibly(t *testing.T) {
	requireEDirUI(t)

	p := edirUIProfile(t, config.SecurityNone, os.Getenv("PADL_EDIR_BASE_DN"))
	t.Setenv(config.EnvVar(p.ID), os.Getenv("PADL_EDIR_PASSWORD"))

	h := start(t, p, nil, config.NewSecrets())

	// Either it is refused, which is the interesting case, or this server
	// permits cleartext binds and there is nothing to check.
	ok := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(h.text(), "Connect failed") {
			ok = true
			break
		}
		if !strings.Contains(h.text(), "not connected") {
			t.Skip("this server allows a simple bind in the clear")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("expected a connect failure dialog:\n%s", h.text())
	}
	h.waitFor("LDAP result 13")

	if strings.Contains(h.text(), os.Getenv("PADL_EDIR_PASSWORD")) {
		t.Error("the password must never reach the screen")
	}
}

// Quick search through the UI, using the eDirectory attribute list.
func TestEDirQuickSearchThroughTheUI(t *testing.T) {
	requireEDirUI(t)

	base := os.Getenv("PADL_EDIR_BASE_DN")
	p := edirUIProfile(t, config.SecurityLDAPS, base)
	t.Setenv(config.EnvVar(p.ID), os.Getenv("PADL_EDIR_PASSWORD"))

	h := start(t, p, nil, config.NewSecrets())
	h.waitFor("Untrusted certificate")
	acceptCertificate(h)
	h.waitConnected()
	h.waitFor(base)

	h.rune('/')
	// The bar offers eDirectory's list, not the generic one.
	h.waitFor("fullName")
	h.typeString("adm")
	h.key(tcell.KeyEnter)

	h.waitUntil("the search to answer", func() bool {
		text := h.text()
		return strings.Contains(text, "for adm") || strings.Contains(text, "Search failed")
	})
	if strings.Contains(h.text(), "Search failed") {
		t.Fatalf("quick search was rejected by the server:\n%s", h.text())
	}
}
