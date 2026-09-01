package config

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// requirePrivate asserts that a file PADL wrote is not readable by others.
//
// Only meaningful on Unix: Go's Chmod on Windows moves the read-only flag and
// nothing else, so the mode bits there say nothing about who can read the file
// — that is settled by the ACL inherited from %AppData%. Asserting 0600 on
// Windows would be testing a fiction, so the check is that the file exists and
// is a regular file.
func requirePrivate(t *testing.T, path, what string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", what, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s is not a regular file", what)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("%s mode = %o, want 600", what, mode)
	}
}

func requirePrivateDir(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("config dir mode = %o, want 700", mode)
	}
}

func TestStoreRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "profiles.yaml")

	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore on a missing file should succeed: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("first run should see no profiles, got %v", s.List())
	}

	p := NewProfile()
	p.ID = "corp-ad"
	p.Name = "Corp AD"
	p.Host = "dc01.corp.example.com"
	p.BindDN = "CN=svc,DC=corp,DC=example,DC=com"
	if err := s.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}

	requirePrivate(t, path, "profiles.yaml — it names bind DNs and hosts")
	requirePrivateDir(t, filepath.Dir(path))

	// The password must never reach the file, whatever else does.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "password:") {
		t.Errorf("profiles.yaml must not carry a password field:\n%s", data)
	}

	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := reloaded.Get("corp-ad")
	if !ok {
		t.Fatal("profile did not survive the round trip")
	}
	if got.Host != p.Host || got.BindDN != p.BindDN || got.Security != p.Security {
		t.Errorf("reloaded = %+v, want %+v", got, p)
	}
}

func TestStorePutReplacesAndDeleteIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.yaml")
	s, _ := LoadStore(path)

	p := NewProfile()
	p.ID = "lab"
	p.Host = "one.example.com"
	p.Bind = BindAnonymous
	if err := s.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	p.Host = "two.example.com"
	if err := s.Put(p); err != nil {
		t.Fatalf("Put again: %v", err)
	}
	if got := s.List(); len(got) != 1 || got[0].Host != "two.example.com" {
		t.Errorf("Put by existing ID should replace, got %+v", got)
	}

	if err := s.Delete("lab"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete("lab"); err != nil {
		t.Errorf("deleting something already gone should be a no-op, got %v", err)
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("List after delete = %v", got)
	}
}

func TestProfileValidate(t *testing.T) {
	valid := func() Profile {
		p := NewProfile()
		p.ID = "lab"
		p.Host = "ldap.example.com"
		p.BindDN = "cn=admin,dc=example,dc=com"
		return p
	}
	base := valid()
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline profile should validate: %v", err)
	}

	cases := map[string]func(*Profile){
		"empty id":             func(p *Profile) { p.ID = "" },
		"uppercase id":         func(p *Profile) { p.ID = "Lab" },
		"id with space":        func(p *Profile) { p.ID = "my lab" },
		"empty host":           func(p *Profile) { p.Host = "" },
		"port out of range":    func(p *Profile) { p.Port = 70000 },
		"unknown security":     func(p *Profile) { p.Security = "tls" },
		"unknown bind":         func(p *Profile) { p.Bind = "sasl" },
		"simple without dn":    func(p *Profile) { p.BindDN = "" },
		"simple without pwref": func(p *Profile) { p.PasswordRef = "" },
	}
	for name, mutate := range cases {
		p := valid()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}

	// Anonymous needs neither a bind DN nor a password source.
	p := valid()
	p.Bind = BindAnonymous
	p.BindDN = ""
	p.PasswordRef = ""
	if err := p.Validate(); err != nil {
		t.Errorf("anonymous profile should validate: %v", err)
	}
}

func TestProfileURLAndDefaults(t *testing.T) {
	p := Profile{Host: "ldap.example.com", Security: SecurityLDAPS}
	if got := p.URL(); got != "ldaps://ldap.example.com:636" {
		t.Errorf("URL = %q", got)
	}
	p.Security = SecurityStartTLS
	if got := p.URL(); got != "ldap://ldap.example.com:389" {
		t.Errorf("StartTLS dials plain first, URL = %q", got)
	}
	p.Port = 3269
	if got := p.URL(); got != "ldap://ldap.example.com:3269" {
		t.Errorf("explicit port ignored, URL = %q", got)
	}
	if got := p.Timeout(); got != DefaultTimeoutSeconds {
		t.Errorf("Timeout = %d, want the default", got)
	}
	if got := p.Limit(); got != DefaultPageSize {
		t.Errorf("Limit = %d, want the default", got)
	}
	if got := (&Profile{ID: "fallback"}).Display(); got != "fallback" {
		t.Errorf("Display should fall back to the ID, got %q", got)
	}
}

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	// Raw is all Fingerprint needs, and building it by hand keeps the test from
	// depending on key generation.
	tmpl.Raw = []byte("fake-der-for-" + cn)
	return tmpl
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint(selfSigned(t, "a"))
	if len(fp) != 32*3-1 {
		t.Errorf("fingerprint %q is not 32 colon-separated hex bytes", fp)
	}
	if fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint %q should be uppercase, to match openssl output", fp)
	}
	if Fingerprint(selfSigned(t, "a")) != fp {
		t.Error("fingerprint should be stable for the same bytes")
	}
	if Fingerprint(selfSigned(t, "b")) == fp {
		t.Error("different certificates must not share a fingerprint")
	}
}

func TestTrustStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.yaml")
	ts, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore on a missing file should succeed: %v", err)
	}
	if _, ok := ts.Get("lab"); ok {
		t.Fatal("nothing should be pinned on a first run")
	}

	pin := PinFor(selfSigned(t, "ldap.example.com"))
	if err := ts.Set("lab", pin); err != nil {
		t.Fatalf("Set: %v", err)
	}

	requirePrivate(t, path, "trust.yaml")

	reloaded, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := reloaded.Get("lab")
	if !ok {
		t.Fatal("pin did not survive the round trip")
	}
	if got.Fingerprint != pin.Fingerprint || got.Subject != pin.Subject {
		t.Errorf("reloaded pin = %+v, want %+v", got, pin)
	}

	if err := reloaded.Delete("lab"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := reloaded.Get("lab"); ok {
		t.Error("deleted pin should be gone, so the next connect re-prompts")
	}
}

// fakeKeyring stands in for the OS keychain: present, empty, or unreachable.
type fakeKeyring struct {
	items       map[string]string
	unavailable error
}

func (f *fakeKeyring) Get(service, user string) (string, error) {
	if f.unavailable != nil {
		return "", f.unavailable
	}
	v, ok := f.items[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f *fakeKeyring) Set(service, user, password string) error {
	if f.unavailable != nil {
		return f.unavailable
	}
	if f.items == nil {
		f.items = map[string]string{}
	}
	f.items[service+"/"+user] = password
	return nil
}

func (f *fakeKeyring) Delete(service, user string) error {
	if f.unavailable != nil {
		return f.unavailable
	}
	if _, ok := f.items[service+"/"+user]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.items, service+"/"+user)
	return nil
}

func simpleProfile(ref PasswordRef) Profile {
	p := NewProfile()
	p.ID = "lab"
	p.Host = "ldap.example.com"
	p.BindDN = "cn=admin,dc=example,dc=com"
	p.PasswordRef = ref
	return p
}

func TestSecretsKeyring(t *testing.T) {
	fk := &fakeKeyring{}
	s := &Secrets{backend: fk}
	p := simpleProfile(PasswordKeyring)

	if _, err := s.Lookup(p); !errors.Is(err, ErrPromptRequired) {
		t.Errorf("an empty keychain should ask the user, got %v", err)
	}
	if err := s.Store(p, "hunter2"); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := s.Lookup(p)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Lookup = %q", got)
	}
	if err := s.Forget(p); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if err := s.Forget(p); err != nil {
		t.Errorf("forgetting a secret that is already gone should be fine, got %v", err)
	}
}

// A headless Linux box with no D-Bus must degrade to a prompt with an
// explanation, not take the whole app down.
func TestSecretsKeyringUnavailableDegradesToPrompt(t *testing.T) {
	fk := &fakeKeyring{unavailable: errors.New("dbus: no session bus")}
	s := &Secrets{backend: fk}

	_, err := s.Lookup(simpleProfile(PasswordKeyring))
	if !errors.Is(err, ErrPromptRequired) {
		t.Fatalf("want ErrPromptRequired, got %v", err)
	}
	var ku *KeyringUnavailableError
	if !errors.As(err, &ku) {
		t.Fatalf("want a KeyringUnavailableError carrying the reason, got %v", err)
	}
	if !strings.Contains(err.Error(), "dbus") {
		t.Errorf("error should keep the underlying reason for the status bar, got %q", err)
	}
}

func TestSecretsPromptAndEnv(t *testing.T) {
	s := &Secrets{backend: &fakeKeyring{}}

	if _, err := s.Lookup(simpleProfile(PasswordPrompt)); !errors.Is(err, ErrPromptRequired) {
		t.Errorf("prompt profiles always ask, got %v", err)
	}

	p := simpleProfile(PasswordEnv)
	if _, err := s.Lookup(p); !errors.Is(err, ErrPromptRequired) {
		t.Errorf("unset env var should fall back to a prompt, got %v", err)
	}
	t.Setenv(EnvVar(p.ID), "from-env")
	got, err := s.Lookup(p)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "from-env" {
		t.Errorf("Lookup = %q, want the env value", got)
	}

	anon := simpleProfile(PasswordKeyring)
	anon.Bind = BindAnonymous
	if got, err := s.Lookup(anon); err != nil || got != "" {
		t.Errorf("anonymous bind needs no secret, got %q / %v", got, err)
	}

	// Storing into a non-keyring profile must say so rather than silently drop
	// the secret.
	if err := s.Store(simpleProfile(PasswordPrompt), "x"); err == nil {
		t.Error("Store on a prompt profile should report that nothing was saved")
	}
}

func TestEnvVar(t *testing.T) {
	cases := map[string]string{
		"lab":     "PADL_PASSWORD_LAB",
		"corp-ad": "PADL_PASSWORD_CORP_AD",
		"a.b_c":   "PADL_PASSWORD_A_B_C",
	}
	for id, want := range cases {
		if got := EnvVar(id); got != want {
			t.Errorf("EnvVar(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestDirHonoursXDGEverywhere(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join("custom", "cfg"))
	want := filepath.Join("custom", "cfg", "padl")
	if got := Dir(); got != want {
		t.Errorf("Dir() = %q, want %q — XDG_CONFIG_HOME wins on every platform so a "+
			"dotfiles setup keeps working under WSL and Git Bash", got, want)
	}
	if got := ProfilesPath(); got != filepath.Join(want, "profiles.yaml") {
		t.Errorf("ProfilesPath() = %q", got)
	}
	if got := TrustPath(); got != filepath.Join(want, "trust.yaml") {
		t.Errorf("TrustPath() = %q", got)
	}
}

// Without XDG_CONFIG_HOME the location is per-platform: %AppData% on Windows,
// ~/.config elsewhere. os.UserConfigDir is only right on Windows — on macOS it
// points at ~/Library/Application Support, which is not where anyone looks for
// a terminal tool's config.
func TestDirDefaultsToThePlatformConvention(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")

	got := Dir()
	if !filepath.IsAbs(got) {
		t.Fatalf("Dir() = %q, want an absolute path", got)
	}
	if filepath.Base(got) != "padl" {
		t.Errorf("Dir() = %q, want it to end in padl", got)
	}

	if runtime.GOOS == "windows" {
		appData, err := os.UserConfigDir()
		if err != nil {
			t.Skip("no user config dir on this machine")
		}
		if want := filepath.Join(appData, "padl"); got != want {
			t.Errorf("Dir() = %q, want %q", got, want)
		}
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory on this machine")
	}
	if want := filepath.Join(home, ".config", "padl"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}

func TestBookmarks(t *testing.T) {
	p := NewProfile()
	p.ID = "lab"
	p.Host = "ldap.example.com"
	p.BindDN = "cn=admin,dc=example,dc=com"

	dn := "uid=jdoe,ou=People,dc=example,dc=com"
	if p.Bookmarked(dn) {
		t.Fatal("a fresh profile has no bookmarks")
	}
	if !p.AddBookmark(dn) {
		t.Fatal("AddBookmark should report that it added one")
	}
	if !p.Bookmarked(dn) {
		t.Error("the DN should now be bookmarked")
	}

	// Adding the same DN again, spelled differently, must not duplicate it.
	if p.AddBookmark("UID=JDOE, OU=People,DC=Example,DC=Com") {
		t.Error("the same DN in different case should not be added twice")
	}
	if len(p.Bookmarks) != 1 {
		t.Errorf("bookmarks = %v, want one entry", p.Bookmarks)
	}

	if p.AddBookmark("   ") {
		t.Error("an empty DN is not a bookmark")
	}

	if !p.RemoveBookmark("uid=jdoe,ou=people,dc=example,dc=com") {
		t.Error("RemoveBookmark should match regardless of case")
	}
	if len(p.Bookmarks) != 0 {
		t.Errorf("bookmarks = %v, want empty", p.Bookmarks)
	}
	if p.RemoveBookmark(dn) {
		t.Error("removing one that is already gone changes nothing")
	}
}

func TestBookmarksSurviveTheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.yaml")
	s, _ := LoadStore(path)

	p := NewProfile()
	p.ID = "lab"
	p.Host = "ldap.example.com"
	p.BindDN = "cn=admin,dc=example,dc=com"
	p.AddBookmark("ou=People,dc=example,dc=com")
	p.AddBookmark("ou=Groups,dc=example,dc=com")
	if err := s.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}

	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, _ := reloaded.Get("lab")
	if len(got.Bookmarks) != 2 || got.Bookmarks[0] != "ou=People,dc=example,dc=com" {
		t.Errorf("bookmarks = %v, want both in order", got.Bookmarks)
	}
}
