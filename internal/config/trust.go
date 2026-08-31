package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Pin records the certificate a profile is expected to present. It exists so a
// server whose cert cannot be verified against the system roots can still be
// reached safely after the operator has eyeballed the fingerprint once.
type Pin struct {
	Fingerprint string    `yaml:"fingerprint"` // SHA-256 of the leaf DER, colon-separated hex
	Subject     string    `yaml:"subject"`
	Issuer      string    `yaml:"issuer"`
	NotAfter    time.Time `yaml:"notAfter"`
	AddedAt     time.Time `yaml:"addedAt"`
}

// Fingerprint renders a certificate's SHA-256 as uppercase colon-separated hex,
// matching what openssl x509 -fingerprint prints.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// PinFor builds a Pin describing cert, stamped now.
func PinFor(cert *x509.Certificate) Pin {
	return Pin{
		Fingerprint: Fingerprint(cert),
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotAfter:    cert.NotAfter,
		AddedAt:     time.Now(),
	}
}

// TrustStore is trust.yaml: the pinned certificate per profile ID.
type TrustStore struct {
	path string

	mu   sync.RWMutex
	pins map[string]Pin
}

type trustFile struct {
	Pins map[string]Pin `yaml:"pins"`
}

// TrustPath is where trust.yaml lives.
func TrustPath() string { return filepath.Join(Dir(), "trust.yaml") }

// LoadTrustStore reads trust.yaml; a missing file yields an empty store.
func LoadTrustStore(path string) (*TrustStore, error) {
	if path == "" {
		path = TrustPath()
	}
	t := &TrustStore{path: path, pins: map[string]Pin{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f trustFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for k, v := range f.Pins {
		t.pins[k] = v
	}
	return t, nil
}

// Path is the file the store reads and writes.
func (t *TrustStore) Path() string { return t.path }

// Get returns the pin for a profile, if one has been recorded.
func (t *TrustStore) Get(profileID string) (Pin, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.pins[profileID]
	return p, ok
}

// Set records a pin for a profile and persists it, replacing any earlier one.
func (t *TrustStore) Set(profileID string, pin Pin) error {
	t.mu.Lock()
	t.pins[profileID] = pin
	t.mu.Unlock()
	return t.Save()
}

// Delete drops a profile's pin, so the next connect re-prompts.
func (t *TrustStore) Delete(profileID string) error {
	t.mu.Lock()
	delete(t.pins, profileID)
	t.mu.Unlock()
	return t.Save()
}

// Save writes trust.yaml at 0600.
func (t *TrustStore) Save() error {
	t.mu.RLock()
	f := trustFile{Pins: map[string]Pin{}}
	for k, v := range t.pins {
		f.Pins[k] = v
	}
	t.mu.RUnlock()
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode trust store: %w", err)
	}
	return writeFilePrivate(t.path, data)
}
