package ldapx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mnorrsken/padl/internal/config"
)

// TrustReason distinguishes the two cases the operator has to judge.
type TrustReason int

const (
	// TrustUntrusted: the certificate does not verify against the system roots
	// and no pin has been recorded for this profile yet.
	TrustUntrusted TrustReason = iota
	// TrustChanged: a pin exists and the server presented a different
	// certificate. This is the case that actually matters.
	TrustChanged
)

// CertTrustError is returned when a TLS peer needs an operator decision. The
// fields are everything the confirmation modal has to show, so the UI never
// needs to parse a certificate itself.
type CertTrustError struct {
	Reason      TrustReason
	Host        string
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
	SANs        []string
	// Existing is the pin that was on file, set only when Reason is TrustChanged.
	Existing *config.Pin
	// VerifyErr is why the certificate failed normal verification, e.g. "x509:
	// certificate signed by unknown authority". Worth showing verbatim.
	VerifyErr error

	cert *x509.Certificate
}

func (e *CertTrustError) Error() string {
	switch e.Reason {
	case TrustChanged:
		return fmt.Sprintf("certificate for %s changed (now %s)", e.Host, e.Fingerprint)
	default:
		return fmt.Sprintf("certificate for %s is not trusted: %v", e.Host, e.VerifyErr)
	}
}

// Pin builds the trust-store entry to write if the operator accepts.
func (e *CertTrustError) Pin() config.Pin { return config.PinFor(e.cert) }

// Expired reports whether the presented certificate is outside its validity
// window right now. Worth calling out separately in the prompt: accepting an
// expired certificate is a different kind of decision from accepting a
// self-signed one.
func (e *CertTrustError) Expired() bool {
	now := time.Now()
	return now.Before(e.NotBefore) || now.After(e.NotAfter)
}

// AsCertTrustError digs a *CertTrustError out of whatever go-ldap wrapped the
// handshake failure in.
func AsCertTrustError(err error) (*CertTrustError, bool) {
	var cte *CertTrustError
	if errors.As(err, &cte) {
		return cte, true
	}
	return nil, false
}

// trustCapture holds the decision the verifier reached. go-ldap does not always
// preserve the handshake error unwrapped, so the verifier records its verdict
// here as well as returning it.
type trustCapture struct {
	err *CertTrustError
}

// tlsConfigFor builds the TLS settings for a profile.
//
// InsecureSkipVerify is on because the verification has to happen in our own
// callback — but note that this also switches off the hostname check, so the
// callback must redo *both* chain building and hostname matching. Skipping the
// hostname half would quietly turn trust-on-first-use into trust-anything.
func tlsConfigFor(host string, pin *config.Pin, capture *trustCapture) *tls.Config {
	return &tls.Config{
		ServerName:         host, // still used for SNI
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // verifyPeer below does the real work
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			err := verifyPeer(host, pin, rawCerts)
			if err != nil {
				var cte *CertTrustError
				if errors.As(err, &cte) && capture != nil {
					capture.err = cte
				}
			}
			return err
		},
	}
}

// NewCertTrustError builds the operator-facing description of a certificate
// that needs a decision. Exported so a caller can construct the same value
// without a live handshake.
func NewCertTrustError(reason TrustReason, host string, cert *x509.Certificate, existing *config.Pin, verifyErr error) *CertTrustError {
	return &CertTrustError{
		Reason:      reason,
		Host:        host,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: config.Fingerprint(cert),
		SANs:        sansOf(cert),
		Existing:    existing,
		VerifyErr:   verifyErr,
		cert:        cert,
	}
}

// verifyPeer implements the trust decision:
//
//  1. Normal verification — chain to a system root *and* hostname match. If it
//     passes, nothing is pinned; PADL stays out of the way for properly issued
//     certificates.
//  2. Otherwise compare the leaf's SHA-256 against the profile's pin. A match
//     means the operator already approved exactly this certificate.
//  3. No pin: TrustUntrusted, for a first-connect prompt.
//  4. Pin present but different: TrustChanged, which needs a louder prompt.
func verifyPeer(host string, pin *config.Pin, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("server presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse server certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(c)
		}
	}

	// DNSName makes Verify do the hostname check too, and it handles bare IP
	// literals via the certificate's IP SANs.
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       hostForVerify(host),
		Intermediates: intermediates,
	})
	if verifyErr == nil {
		return nil
	}

	if pin != nil {
		if pin.Fingerprint == config.Fingerprint(leaf) {
			return nil
		}
		existing := *pin
		return NewCertTrustError(TrustChanged, host, leaf, &existing, verifyErr)
	}
	return NewCertTrustError(TrustUntrusted, host, leaf, nil, verifyErr)
}

// hostForVerify strips a port and IPv6 brackets, leaving what belongs in a
// hostname check.
func hostForVerify(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// sansOf flattens the subject alternative names worth showing in the prompt.
func sansOf(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses))
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, c.EmailAddresses...)
	return out
}
