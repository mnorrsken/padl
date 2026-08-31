package ldapx

import (
	"reflect"
	"strings"
	"testing"
)

func entry(dn string, classes ...string) Entry {
	e := Entry{DN: dn, Subordinates: -1}
	if len(classes) > 0 {
		vals := make([][]byte, len(classes))
		for i, c := range classes {
			vals[i] = []byte(c)
		}
		e.Attributes = append(e.Attributes, Attribute{Name: "objectClass", Values: vals})
	}
	return e
}

func TestRDN(t *testing.T) {
	cases := map[string]string{
		"uid=jdoe,ou=People,dc=example,dc=com": "uid=jdoe",
		"dc=example,dc=com":                    "dc=example",
		"dc=com":                               "dc=com",
		"":                                     "",
		// A comma inside an escaped value must not split the RDN.
		`cn=Doe\, John,ou=People,dc=example,dc=com`: `cn=Doe\, John`,
		// A trailing backslash must not run off the end.
		`cn=odd\`: `cn=odd\`,
	}
	for dn, want := range cases {
		if got := RDN(dn); got != want {
			t.Errorf("RDN(%q) = %q, want %q", dn, got, want)
		}
	}
}

func TestSortEntriesPutsContainersFirst(t *testing.T) {
	entries := []Entry{
		entry("uid=zoe,dc=example,dc=com", "inetOrgPerson"),
		entry("ou=People,dc=example,dc=com", "organizationalUnit"),
		entry("uid=adam,dc=example,dc=com", "inetOrgPerson"),
		entry("ou=Groups,dc=example,dc=com", "organizationalUnit"),
	}
	SortEntries(entries)
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.RDN()
	}
	want := []string{"ou=Groups", "ou=People", "uid=adam", "uid=zoe"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestKindOf(t *testing.T) {
	cases := []struct {
		classes []string
		want    Kind
	}{
		{[]string{"organizationalUnit"}, KindContainer},
		{[]string{"top", "person", "organizationalPerson", "inetOrgPerson"}, KindPerson},
		{[]string{"top", "groupOfNames"}, KindGroup},
		{[]string{"top", "computer"}, KindComputer},
		{[]string{"top", "someUnknownClass"}, KindOther},
		{nil, KindOther},
		// AD users carry organizationalUnit-free class lists but sit under one;
		// classification must come from the entry's own classes.
		{[]string{"top", "user"}, KindPerson},
	}
	for _, c := range cases {
		e := entry("cn=x", c.classes...)
		if got := KindOf(&e); got != c.want {
			t.Errorf("KindOf(%v) = %v, want %v", c.classes, got, c.want)
		}
	}
}

func TestEntryGetIsCaseInsensitive(t *testing.T) {
	e := entry("cn=x", "inetOrgPerson")
	if got := e.Get("OBJECTCLASS"); len(got) != 1 || got[0] != "inetOrgPerson" {
		t.Errorf("Get(OBJECTCLASS) = %v", got)
	}
	if got := e.First("objectclass"); got != "inetOrgPerson" {
		t.Errorf("First = %q", got)
	}
	if got := e.Get("missing"); got != nil {
		t.Errorf("Get(missing) = %v, want nil", got)
	}
}

func TestApplySubordinateHints(t *testing.T) {
	set := func(name, value string) Entry {
		e := Entry{DN: "ou=x", Subordinates: -1}
		e.Attributes = append(e.Attributes, Attribute{Name: name, Values: [][]byte{[]byte(value)}})
		applySubordinateHints(&e)
		return e
	}

	e := set("numSubordinates", "7")
	if e.Subordinates != 7 || e.HasSubordinates == nil || !*e.HasSubordinates {
		t.Errorf("numSubordinates=7 gave %+v", e)
	}
	e = set("numSubordinates", "0")
	if e.Subordinates != 0 || e.HasSubordinates == nil || *e.HasSubordinates {
		t.Errorf("numSubordinates=0 gave %+v", e)
	}
	e = set("subordinateCount", "3") // eDirectory spelling
	if e.Subordinates != 3 {
		t.Errorf("subordinateCount=3 gave %+v", e)
	}
	e = set("hasSubordinates", "TRUE")
	if e.HasSubordinates == nil || !*e.HasSubordinates {
		t.Errorf("hasSubordinates=TRUE gave %+v", e)
	}
	if e.Subordinates != -1 {
		t.Errorf("hasSubordinates says nothing about the count, got %d", e.Subordinates)
	}
	e = set("hasSubordinates", "FALSE")
	if e.HasSubordinates == nil || *e.HasSubordinates {
		t.Errorf("hasSubordinates=FALSE gave %+v", e)
	}
	// A server that answers none of them leaves the tree to guess, which must
	// stay distinguishable from a definite "no children".
	bare := Entry{DN: "ou=x", Subordinates: -1}
	applySubordinateHints(&bare)
	if bare.HasSubordinates != nil {
		t.Errorf("silent server should leave HasSubordinates nil, got %v", *bare.HasSubordinates)
	}
}

func TestValidateDN(t *testing.T) {
	valid := []string{
		"uid=admin,ou=people,dc=example,dc=com",
		"cn=admin,dc=example,dc=com",
		`cn=Doe\, John,ou=People,dc=example,dc=com`,
		"dc=com",
	}
	for _, dn := range valid {
		if err := ValidateDN(dn); err != nil {
			t.Errorf("ValidateDN(%q) = %v, want nil", dn, err)
		}
	}

	// The mistake people actually make: a bare username where a DN belongs.
	err := ValidateDN("admin")
	if err == nil {
		t.Fatal("a bare username is not a DN")
	}
	if !strings.Contains(err.Error(), "uid=admin,ou=people") {
		t.Errorf("the message should show what a DN looks like, got %q", err)
	}

	if err := ValidateDN("   "); err == nil {
		t.Error("an empty bind DN should be rejected")
	}
}
