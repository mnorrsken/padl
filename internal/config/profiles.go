// Package config handles PADL's on-disk state: server profiles, pinned
// certificates and bind secrets. Nothing in here talks to a directory server.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Security is the transport used to reach a directory server.
type Security string

const (
	SecurityNone     Security = "none"     // plain LDAP, port 389
	SecurityStartTLS Security = "starttls" // plain connect upgraded via StartTLS
	SecurityLDAPS    Security = "ldaps"    // TLS from the first byte, port 636
)

// BindMethod is how PADL authenticates once connected.
type BindMethod string

const (
	BindAnonymous BindMethod = "anonymous"
	BindSimple    BindMethod = "simple"
)

// PasswordRef says where a profile's bind password comes from. The password
// itself is never stored in the profile file.
type PasswordRef string

const (
	// PasswordKeyring stores the secret in the OS keychain under service
	// "padl", keyed by profile ID.
	PasswordKeyring PasswordRef = "keyring"
	// PasswordPrompt asks on every connect and keeps nothing.
	PasswordPrompt PasswordRef = "prompt"
	// PasswordEnv reads PADL_PASSWORD_<ID>, for scripting and CI.
	PasswordEnv PasswordRef = "env"
)

const (
	// DefaultTimeoutSeconds bounds a single LDAP operation.
	DefaultTimeoutSeconds = 15
	// DefaultPageSize caps how many children one container lists.
	DefaultPageSize = 500
)

// Profile is one configured directory server.
type Profile struct {
	ID             string      `yaml:"id"`
	Name           string      `yaml:"name"`
	Host           string      `yaml:"host"`
	Port           int         `yaml:"port"`
	Security       Security    `yaml:"security"`
	Bind           BindMethod  `yaml:"bind"`
	BindDN         string      `yaml:"bindDN,omitempty"`
	PasswordRef    PasswordRef `yaml:"passwordRef,omitempty"`
	BaseDN         string      `yaml:"baseDN,omitempty"`
	TimeoutSeconds int         `yaml:"timeoutSeconds,omitempty"`
	PageSize       int         `yaml:"pageSize,omitempty"`
}

// DefaultPort is the conventional port for a transport.
func DefaultPort(s Security) int {
	if s == SecurityLDAPS {
		return 636
	}
	return 389
}

// Addr is the host:port PADL dials.
func (p *Profile) Addr() string {
	port := p.Port
	if port == 0 {
		port = DefaultPort(p.Security)
	}
	return fmt.Sprintf("%s:%d", p.Host, port)
}

// URL is the ldap:// or ldaps:// form of Addr, as go-ldap's DialURL wants it.
func (p *Profile) URL() string {
	scheme := "ldap"
	if p.Security == SecurityLDAPS {
		scheme = "ldaps"
	}
	return scheme + "://" + p.Addr()
}

// Timeout is TimeoutSeconds with the default applied.
func (p *Profile) Timeout() int {
	if p.TimeoutSeconds <= 0 {
		return DefaultTimeoutSeconds
	}
	return p.TimeoutSeconds
}

// Limit is PageSize with the default applied.
func (p *Profile) Limit() int {
	if p.PageSize <= 0 {
		return DefaultPageSize
	}
	return p.PageSize
}

// Display is the human label for lists; falls back to the ID.
func (p *Profile) Display() string {
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return p.ID
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Validate reports whether the profile is usable, with a message aimed at the
// person filling in the form rather than at a log file.
func (p *Profile) Validate() error {
	switch {
	case strings.TrimSpace(p.ID) == "":
		return fmt.Errorf("id is required")
	case !idPattern.MatchString(p.ID):
		return fmt.Errorf("id %q must be lowercase letters, digits, dot, dash or underscore", p.ID)
	case strings.TrimSpace(p.Host) == "":
		return fmt.Errorf("host is required")
	case p.Port < 0 || p.Port > 65535:
		return fmt.Errorf("port %d is out of range", p.Port)
	}
	switch p.Security {
	case SecurityNone, SecurityStartTLS, SecurityLDAPS:
	default:
		return fmt.Errorf("security %q must be none, starttls or ldaps", p.Security)
	}
	switch p.Bind {
	case BindAnonymous:
	case BindSimple:
		if strings.TrimSpace(p.BindDN) == "" {
			return fmt.Errorf("bind DN is required for a simple bind")
		}
		switch p.PasswordRef {
		case PasswordKeyring, PasswordPrompt, PasswordEnv:
		default:
			return fmt.Errorf("passwordRef %q must be keyring, prompt or env", p.PasswordRef)
		}
	default:
		return fmt.Errorf("bind %q must be anonymous or simple", p.Bind)
	}
	return nil
}

// NewProfile returns a profile with sensible defaults filled in, ready for the
// add form.
func NewProfile() Profile {
	return Profile{
		Port:           DefaultPort(SecurityLDAPS),
		Security:       SecurityLDAPS,
		Bind:           BindSimple,
		PasswordRef:    PasswordKeyring,
		TimeoutSeconds: DefaultTimeoutSeconds,
		PageSize:       DefaultPageSize,
	}
}

// Store is the profiles.yaml file. It is safe for concurrent use.
type Store struct {
	path string

	mu       sync.RWMutex
	profiles []Profile
}

type profilesFile struct {
	Profiles []Profile `yaml:"profiles"`
}

// ProfilesPath is where profiles.yaml lives, honouring XDG_CONFIG_HOME.
func ProfilesPath() string { return filepath.Join(Dir(), "profiles.yaml") }

// Dir is PADL's config directory.
//
// $XDG_CONFIG_HOME when set, otherwise ~/.config — including on macOS, where
// os.UserConfigDir would point at ~/Library/Application Support. A terminal tool
// whose config sits next to everything else in ~/.config is the one people can
// actually find and put in a dotfiles repo.
func Dir() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); dir != "" {
		return filepath.Join(dir, "padl")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Nothing sensible left to do but stay relative rather than crash at
		// startup; the -paths flag will make it obvious what happened.
		return filepath.Join(".padl")
	}
	return filepath.Join(home, ".config", "padl")
}

// LoadStore reads profiles.yaml. A missing file is not an error — it yields an
// empty store, which is exactly what a first run should see.
func LoadStore(path string) (*Store, error) {
	if path == "" {
		path = ProfilesPath()
	}
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f profilesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s.profiles = f.Profiles
	s.sort()
	return s, nil
}

// Path is the file the store reads and writes.
func (s *Store) Path() string { return s.path }

func (s *Store) sort() {
	sort.SliceStable(s.profiles, func(i, j int) bool {
		return strings.ToLower(s.profiles[i].Display()) < strings.ToLower(s.profiles[j].Display())
	})
}

// List returns a copy of the profiles, sorted by display name.
func (s *Store) List() []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Profile, len(s.profiles))
	copy(out, s.profiles)
	return out
}

// Get looks a profile up by ID.
func (s *Store) Get(id string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

// Put inserts or replaces a profile by ID and persists the file.
func (s *Store) Put(p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	replaced := false
	for i := range s.profiles {
		if s.profiles[i].ID == p.ID {
			s.profiles[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		s.profiles = append(s.profiles, p)
	}
	s.sort()
	s.mu.Unlock()
	return s.Save()
}

// Delete removes a profile by ID and persists the file. Removing something that
// is not there is a no-op, not an error.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	kept := s.profiles[:0]
	for _, p := range s.profiles {
		if p.ID != id {
			kept = append(kept, p)
		}
	}
	s.profiles = kept
	s.mu.Unlock()
	return s.Save()
}

// Save writes profiles.yaml at 0600 via a temp file and rename, so a crash
// mid-write cannot leave a truncated config behind.
func (s *Store) Save() error {
	s.mu.RLock()
	f := profilesFile{Profiles: s.profiles}
	s.mu.RUnlock()
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode profiles: %w", err)
	}
	return writeFilePrivate(s.path, data)
}

// writeFilePrivate writes data to path with mode 0600, creating the parent
// directory as 0700 if needed.
func writeFilePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}
