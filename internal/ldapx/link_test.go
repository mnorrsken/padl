package ldapx

import (
	"reflect"
	"testing"
)

var testBases = []string{"dc=example,dc=com", "CN=Configuration,dc=example,dc=com"}

// Plenty of ordinary attribute values parse as a DN by accident. Requiring the
// value to live inside a published naming context is what keeps them from
// becoming bogus links.
func TestIsDNUnderRejectsAccidentalDNs(t *testing.T) {
	links := []string{
		"uid=jdoe,ou=People,dc=example,dc=com",
		"dc=example,dc=com",
		`cn=Doe\, John,ou=People,dc=example,dc=com`,
		"CN=Schema,CN=Configuration,dc=example,dc=com",
		"UID=JDOE,OU=PEOPLE,DC=EXAMPLE,DC=COM",
	}
	for _, v := range links {
		if !IsDNUnder(v, testBases) {
			t.Errorf("IsDNUnder(%q) = false, want true", v)
		}
	}

	notLinks := []string{
		"John Doe",
		"Systems Engineer",
		"jdoe@example.com",
		"inetOrgPerson",
		"512 (NORMAL_ACCOUNT)",
		"2024-01-15 10:30:00 CET",
		"<binary, 16 bytes>",
		"S-1-5-21-1-2-3-512",
		"",
		"   ",
		// These do parse as DNs, which is exactly why the base check matters.
		"x=",
		"cn=whatever",
		"http://example.com/a=b",
		"uid=jdoe,ou=People,dc=other,dc=com",
	}
	for _, v := range notLinks {
		if IsDNUnder(v, testBases) {
			t.Errorf("IsDNUnder(%q) = true, want false", v)
		}
	}

	if IsDNUnder("uid=jdoe,dc=example,dc=com", nil) {
		t.Error("with no bases nothing is navigable")
	}
}

func TestBestBasePrefersTheMostSpecific(t *testing.T) {
	dn := "CN=Sites,CN=Configuration,dc=example,dc=com"
	if got := BestBase(dn, testBases); got != "CN=Configuration,dc=example,dc=com" {
		t.Errorf("BestBase = %q, want the nested partition", got)
	}
	if got := BestBase("ou=People,dc=example,dc=com", testBases); got != "dc=example,dc=com" {
		t.Errorf("BestBase = %q", got)
	}
	if got := BestBase("dc=other,dc=com", testBases); got != "" {
		t.Errorf("BestBase = %q, want empty", got)
	}
}

func TestPathFrom(t *testing.T) {
	base := "dc=example,dc=com"
	got := PathFrom(base, "uid=jdoe,ou=People,dc=example,dc=com")
	want := []string{
		"dc=example,dc=com",
		"ou=People,dc=example,dc=com",
		"uid=jdoe,ou=People,dc=example,dc=com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PathFrom = %v, want %v", got, want)
	}

	// The base itself is a path of one.
	if got := PathFrom(base, "DC=Example,DC=Com"); !reflect.DeepEqual(got, []string{base}) {
		t.Errorf("PathFrom(base, base) = %v, want just the base", got)
	}

	if got := PathFrom(base, "uid=jdoe,dc=other,dc=com"); got != nil {
		t.Errorf("PathFrom outside the base = %v, want nil", got)
	}

	// Escaped commas must not split a component into two tree levels.
	got = PathFrom(base, `cn=Doe\, John,ou=People,dc=example,dc=com`)
	if len(got) != 3 {
		t.Errorf("PathFrom = %v, want three levels", got)
	}
}
