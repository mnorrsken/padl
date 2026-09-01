package ldapx

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestQuickFilterShape(t *testing.T) {
	attrs := []string{"cn", "sn", "mail"}

	// One term needs no conjunction wrapping it.
	got := QuickFilterFor([]string{"mar"}, attrs)
	want := "(|(cn=mar*)(sn=mar*)(mail=mar*))"
	if got != want {
		t.Errorf("one term = %q, want %q", got, want)
	}

	// Two terms are ANDed, each ORed across the attributes.
	got = QuickFilterFor([]string{"mar", "nor"}, attrs)
	want = "(&(|(cn=mar*)(sn=mar*)(mail=mar*))(|(cn=nor*)(sn=nor*)(mail=nor*)))"
	if got != want {
		t.Errorf("two terms = %q, want %q", got, want)
	}

	if got := QuickFilterFor(nil, attrs); got != "" {
		t.Errorf("no terms = %q, want empty", got)
	}
	if got := QuickFilterFor([]string{"mar"}, nil); got != "" {
		t.Errorf("no attributes = %q, want empty", got)
	}
}

// Whatever the builder produces has to be a filter the LDAP library will
// actually compile, or it fails at the server instead of here.
func TestQuickFilterCompiles(t *testing.T) {
	inputs := []string{
		"mar",
		"mar nor",
		"a b c d",
		"O'Brien",
		"jörg",
		"mar*son",
		"has(paren)",
		`back\slash`,
		"trailing*",
		"  spaced   out  ",
	}
	for _, v := range []Vendor{VendorGeneric, VendorActiveDirectory, VendorEDirectory, VendorLLDAP} {
		for _, in := range inputs {
			filter := QuickFilter(in, v)
			if filter == "" {
				t.Errorf("%v: %q produced no filter", v, in)
				continue
			}
			if _, err := ldap.CompileFilter(filter); err != nil {
				t.Errorf("%v: %q produced an uncompilable filter %q: %v", v, in, filter, err)
			}
		}
	}
}

func TestQuickFilterEscapesDangerousInput(t *testing.T) {
	// Parentheses and backslashes must not be able to break out of the value
	// and change the filter's structure.
	got := QuickFilterFor([]string{"a)(objectClass=*"}, []string{"cn"})
	if strings.Contains(got, "a)(objectClass=") {
		t.Errorf("input escaped its value and rewrote the filter: %q", got)
	}
	if _, err := ldap.CompileFilter(got); err != nil {
		t.Errorf("escaped filter does not compile: %q: %v", got, err)
	}

	if got := QuickFilterFor([]string{`a\b`}, []string{"cn"}); !strings.Contains(got, `\5c`) {
		t.Errorf("backslash not escaped: %q", got)
	}
	if got := QuickFilterFor([]string{"a\x00b"}, []string{"cn"}); !strings.Contains(got, `\00`) {
		t.Errorf("NUL not escaped: %q", got)
	}
}

// A wildcard the user typed is theirs to keep; the builder only adds one when
// there is none.
func TestQuickFilterHonoursTypedWildcards(t *testing.T) {
	cases := map[string]string{
		"mar":     "(|(cn=mar*))",
		"mar*":    "(|(cn=mar*))",
		"*son":    "(|(cn=*son))",
		"mar*son": "(|(cn=mar*son))",
	}
	for in, want := range cases {
		if got := QuickFilterFor([]string{in}, []string{"cn"}); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

// Anything starting with "(" is the user writing a filter by hand, and must
// reach the server exactly as typed.
func TestRawFiltersPassThroughUntouched(t *testing.T) {
	raw := []string{
		"(objectClass=*)",
		"(&(objectClass=person)(cn=jdoe))",
		"  (uid=jdoe)  ",
	}
	for _, in := range raw {
		if !IsRawFilter(in) {
			t.Errorf("%q should be treated as a raw filter", in)
		}
		if got := QuickFilter(in, VendorGeneric); got != strings.TrimSpace(in) {
			t.Errorf("QuickFilter(%q) = %q, want it unchanged", in, got)
		}
	}

	for _, in := range []string{"mar", "uid=jdoe", "", "objectClass=*"} {
		if IsRawFilter(in) {
			t.Errorf("%q is not a raw filter", in)
		}
	}
}

// The lists differ per vendor because a single broad one does not work: on
// lldap a substring match on sn or givenName matches nothing and takes the
// whole OR with it.
func TestQuickSearchAttributesAreVendorSpecific(t *testing.T) {
	ad := QuickSearchAttributes(VendorActiveDirectory)
	if !contains(ad, "sAMAccountName") || !contains(ad, "userPrincipalName") {
		t.Errorf("Active Directory should be searchable by the names people use: %v", ad)
	}
	if contains(ad, "uid") {
		t.Errorf("uid only exists on AD with the RFC 2307 extension, so it should not be assumed: %v", ad)
	}

	lldap := QuickSearchAttributes(VendorLLDAP)
	for _, bad := range []string{"sn", "givenName", "memberOf"} {
		if contains(lldap, bad) {
			t.Errorf("%s cannot be substring-matched on lldap and poisons the OR: %v", bad, lldap)
		}
	}
	if !contains(lldap, "uid") || !contains(lldap, "cn") {
		t.Errorf("lldap must at least search uid and cn: %v", lldap)
	}

	edir := QuickSearchAttributes(VendorEDirectory)
	if !contains(edir, "fullName") {
		t.Errorf("eDirectory carries fullName: %v", edir)
	}

	generic := QuickSearchAttributes(VendorGeneric)
	if !reflect.DeepEqual(QuickSearchAttributes(VendorOpenLDAP), generic) {
		t.Error("OpenLDAP is standards-compliant, so it uses the generic list")
	}
	for _, want := range []string{"cn", "sn", "givenName", "mail", "uid"} {
		if !contains(generic, want) {
			t.Errorf("the generic list should include %s: %v", want, generic)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
