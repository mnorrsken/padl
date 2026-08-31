package ldapx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/mnorrsken/padl/internal/config"
)

// issueCert makes a self-signed leaf for host, valid over the given window.
func issueCert(t *testing.T, host string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"PADL Test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// handshake runs one TLS handshake against a throwaway local listener with the
// given server certificate and PADL's client config, returning whatever the
// client's verifier decided.
//
// A real socket rather than net.Pipe: when the verifier rejects a certificate
// the client writes a TLS alert, and on an unbuffered pipe with no reader left
// that write blocks until its deadline.
func handshake(t *testing.T, host string, srvCert tls.Certificate, pin *config.Pin) (error, *trustCapture) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		s := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{srvCert}})
		_ = s.Handshake()
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	capture := &trustCapture{}
	c := tls.Client(raw, tlsConfigFor(host, pin, capture))
	return c.Handshake(), capture
}

func TestVerifierPromptsOnFirstConnect(t *testing.T) {
	now := time.Now()
	cert := issueCert(t, "ldap.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))

	err, capture := handshake(t, "ldap.example.test", cert, nil)
	cte, ok := AsCertTrustError(err)
	if !ok {
		t.Fatalf("want *CertTrustError, got %v", err)
	}
	if cte.Reason != TrustUntrusted {
		t.Errorf("Reason = %v, want TrustUntrusted", cte.Reason)
	}
	if want := config.Fingerprint(cert.Leaf); cte.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", cte.Fingerprint, want)
	}
	if cte.VerifyErr == nil {
		t.Error("VerifyErr should say why normal verification failed")
	}
	if cte.Expired() {
		t.Error("a currently-valid certificate should not report as expired")
	}
	if capture.err == nil {
		t.Error("verdict should also be recorded in the capture, since go-ldap may rewrap the error")
	}
}

func TestVerifierAcceptsMatchingPin(t *testing.T) {
	now := time.Now()
	cert := issueCert(t, "ldap.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))
	pin := config.PinFor(cert.Leaf)

	if err, _ := handshake(t, "ldap.example.test", cert, &pin); err != nil {
		t.Fatalf("pinned certificate should connect silently, got %v", err)
	}
}

func TestVerifierRejectsChangedCert(t *testing.T) {
	now := time.Now()
	old := issueCert(t, "ldap.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))
	fresh := issueCert(t, "ldap.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))
	pin := config.PinFor(old.Leaf)

	err, _ := handshake(t, "ldap.example.test", fresh, &pin)
	cte, ok := AsCertTrustError(err)
	if !ok {
		t.Fatalf("want *CertTrustError, got %v", err)
	}
	if cte.Reason != TrustChanged {
		t.Fatalf("Reason = %v, want TrustChanged", cte.Reason)
	}
	if cte.Existing == nil || cte.Existing.Fingerprint != pin.Fingerprint {
		t.Error("the prompt needs the previous pin to show what changed")
	}
	if cte.Fingerprint == pin.Fingerprint {
		t.Error("new fingerprint should differ from the pinned one")
	}
}

// A pin must not paper over the hostname check: the whole point of redoing
// verification by hand is that InsecureSkipVerify also disables it.
func TestVerifierChecksHostnameNotJustChain(t *testing.T) {
	now := time.Now()
	cert := issueCert(t, "other.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))

	err, _ := handshake(t, "ldap.example.test", cert, nil)
	cte, ok := AsCertTrustError(err)
	if !ok {
		t.Fatalf("want *CertTrustError, got %v", err)
	}
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	if !errors.As(cte.VerifyErr, &hostErr) && !errors.As(cte.VerifyErr, &authErr) {
		t.Errorf("VerifyErr = %v, want a hostname or authority failure", cte.VerifyErr)
	}
}

func TestVerifierFlagsExpiredCert(t *testing.T) {
	now := time.Now()
	cert := issueCert(t, "ldap.example.test", now.Add(-72*time.Hour), now.Add(-24*time.Hour))

	err, _ := handshake(t, "ldap.example.test", cert, nil)
	cte, ok := AsCertTrustError(err)
	if !ok {
		t.Fatalf("want *CertTrustError, got %v", err)
	}
	if !cte.Expired() {
		t.Error("Expired() should be true so the prompt can call it out separately")
	}
}

func TestHostForVerify(t *testing.T) {
	cases := map[string]string{
		"ldap.example.test":     "ldap.example.test",
		"ldap.example.test:636": "ldap.example.test",
		"192.0.2.10:389":        "192.0.2.10",
		"[2001:db8::1]:636":     "2001:db8::1",
		"2001:db8::1":           "2001:db8::1",
	}
	for in, want := range cases {
		if got := hostForVerify(in); got != want {
			t.Errorf("hostForVerify(%q) = %q, want %q", in, got, want)
		}
	}
}
