package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
)

// KeyringService is the service name PADL stores secrets under.
const KeyringService = "padl"

// ErrPromptRequired means the caller must ask the user for the password. It is
// returned for profiles configured to prompt, for a keyring entry that is not
// there yet, and for a keyring that cannot be reached at all — in every case
// the right move for the UI is the same: show the password field.
var ErrPromptRequired = errors.New("password prompt required")

// KeyringUnavailableError reports that the OS keychain could not be reached,
// which is normal on a headless Linux box with no libsecret or D-Bus session.
// It unwraps to ErrPromptRequired so callers can prompt without special-casing
// it, while still having a Reason worth putting on the status bar.
type KeyringUnavailableError struct {
	Reason error
}

func (e *KeyringUnavailableError) Error() string {
	return fmt.Sprintf("OS keychain unavailable (%v); enter the password manually", e.Reason)
}

func (e *KeyringUnavailableError) Unwrap() error { return ErrPromptRequired }

// EnvVar is the environment variable holding a profile's password when its
// PasswordRef is PasswordEnv, e.g. profile "corp-ad" reads PADL_PASSWORD_CORP_AD.
func EnvVar(profileID string) string {
	var b strings.Builder
	b.WriteString("PADL_PASSWORD_")
	for _, r := range strings.ToUpper(profileID) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// Secrets resolves and stores bind passwords. The zero value is usable and
// talks to the real OS keychain; tests substitute keyringBackend.
type Secrets struct {
	// backend is nil in production, meaning "use go-keyring".
	backend keyringBackend
}

// keyringBackend is the slice of go-keyring PADL uses, so tests can fake a
// keychain that is missing, empty or populated without touching the real one.
type keyringBackend interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

type realKeyring struct{}

func (realKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (realKeyring) Set(service, user, pw string) error       { return keyring.Set(service, user, pw) }
func (realKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

// NewSecrets returns a Secrets backed by the OS keychain.
func NewSecrets() *Secrets { return &Secrets{backend: realKeyring{}} }

func (s *Secrets) kr() keyringBackend {
	if s.backend == nil {
		return realKeyring{}
	}
	return s.backend
}

// Lookup resolves the bind password for a profile without any user
// interaction. Callers must treat ErrPromptRequired as "ask the user", not as
// a failure.
func (s *Secrets) Lookup(p Profile) (string, error) {
	if p.Bind == BindAnonymous {
		return "", nil
	}
	switch p.PasswordRef {
	case PasswordPrompt:
		return "", ErrPromptRequired
	case PasswordEnv:
		v, ok := os.LookupEnv(EnvVar(p.ID))
		if !ok || v == "" {
			return "", fmt.Errorf("%s is not set: %w", EnvVar(p.ID), ErrPromptRequired)
		}
		return v, nil
	case PasswordKeyring:
		v, err := s.kr().Get(KeyringService, p.ID)
		switch {
		case err == nil:
			return v, nil
		case errors.Is(err, keyring.ErrNotFound):
			return "", ErrPromptRequired
		default:
			return "", &KeyringUnavailableError{Reason: err}
		}
	default:
		return "", fmt.Errorf("profile %q has no password source configured: %w", p.ID, ErrPromptRequired)
	}
}

// Store saves a password for later connects. It is only meaningful for
// keyring-backed profiles; for the others it reports what it did instead so
// the UI can say "not saved" rather than silently dropping the secret.
func (s *Secrets) Store(p Profile, password string) error {
	if p.PasswordRef != PasswordKeyring {
		return fmt.Errorf("profile %q does not use the keychain, password not saved", p.ID)
	}
	if err := s.kr().Set(KeyringService, p.ID, password); err != nil {
		return &KeyringUnavailableError{Reason: err}
	}
	return nil
}

// Forget removes a stored password. A secret that was never there is not an
// error.
func (s *Secrets) Forget(p Profile) error {
	err := s.kr().Delete(KeyringService, p.ID)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return &KeyringUnavailableError{Reason: err}
}
