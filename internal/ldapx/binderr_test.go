package ldapx

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// The server's diagnostic is often the only thing that says what to do — lldap
// answers a wrong bind DN with the exact shape it expects — so it has to
// survive redaction.
func TestRedactBindErrorKeepsTheServerDiagnostic(t *testing.T) {
	src := &ldap.Error{
		ResultCode: ldap.LDAPResultNamingViolation,
		Err: errors.New(`Unexpected DN format. Got "cn=admin,dc=example,dc=com", ` +
			`expected: "uid=id,ou=people,dc=example,dc=com"`),
	}

	got := redactBindError(src, "hunter2-secret").Error()
	if !strings.Contains(got, "LDAP result 64") {
		t.Errorf("the result code should survive, got %q", got)
	}
	if !strings.Contains(got, "uid=id,ou=people,dc=example,dc=com") {
		t.Errorf("the server's diagnostic should survive, got %q", got)
	}
}

func TestRedactBindErrorScrubsThePassword(t *testing.T) {
	password := "hunter2-secret"
	src := &ldap.Error{
		ResultCode: ldap.LDAPResultInvalidCredentials,
		Err:        errors.New("rejected credentials " + password + " for user"),
	}

	got := redactBindError(src, password).Error()
	if strings.Contains(got, password) {
		t.Fatalf("the password reached the message: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("the scrub should be visible rather than silent, got %q", got)
	}

	// A plain error still gets scrubbed.
	plain := redactBindError(errors.New("dial failed for "+password), password).Error()
	if strings.Contains(plain, password) {
		t.Errorf("the password reached a non-LDAP error: %q", plain)
	}
}

// Blanking every occurrence of a very short password would mangle the message
// without protecting anything worth protecting.
func TestRedactBindErrorLeavesShortSecretsAlone(t *testing.T) {
	got := redactBindError(&ldap.Error{
		ResultCode: ldap.LDAPResultInvalidCredentials,
		Err:        errors.New("no such user abc"),
	}, "abc").Error()
	if !strings.Contains(got, "no such user abc") {
		t.Errorf("a three-character secret should not be substituted, got %q", got)
	}
}

// go-ldap restates the result code as the error text for some failures; that
// adds nothing next to the code PADL already prints.
func TestRedactBindErrorDropsRedundantText(t *testing.T) {
	got := redactBindError(&ldap.Error{
		ResultCode: ldap.LDAPResultInvalidCredentials,
		Err:        errors.New("Invalid Credentials"),
	}, "").Error()
	if strings.Count(got, "Invalid Credentials") != 1 {
		t.Errorf("the code name should appear once, got %q", got)
	}
}
