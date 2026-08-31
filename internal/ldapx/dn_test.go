package ldapx

import (
	"reflect"
	"testing"
)

func TestSplitDN(t *testing.T) {
	cases := []struct {
		dn   string
		want []string
	}{
		{"uid=jdoe,ou=People,dc=example,dc=com", []string{"uid=jdoe", "ou=People", "dc=example", "dc=com"}},
		{"dc=com", []string{"dc=com"}},
		{"", nil},
		{"  uid=jdoe , ou=People ", []string{"uid=jdoe", "ou=People"}},
		{`cn=Doe\, John,ou=People,dc=example,dc=com`, []string{`cn=Doe\, John`, "ou=People", "dc=example", "dc=com"}},
	}
	for _, c := range cases {
		if got := SplitDN(c.dn); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitDN(%q) = %v, want %v", c.dn, got, c.want)
		}
	}
}

func TestEqualDN(t *testing.T) {
	if !EqualDN("DC=Example,DC=Com", "dc=example,dc=com") {
		t.Error("DN comparison should ignore case")
	}
	if !EqualDN("uid=jdoe, ou=People,dc=example,dc=com", "uid=jdoe,ou=People,dc=example,dc=com") {
		t.Error("DN comparison should ignore whitespace around components")
	}
	if EqualDN("ou=People,dc=example,dc=com", "dc=example,dc=com") {
		t.Error("different DNs must not compare equal")
	}
	if EqualDN("uid=jdoe,dc=example,dc=com", "uid=asmith,dc=example,dc=com") {
		t.Error("different RDNs must not compare equal")
	}
}

func TestDepthUnderAndAncestorUnder(t *testing.T) {
	base := "dc=example,dc=com"
	cases := []struct {
		child    string
		depth    int
		ancestor string
	}{
		{"ou=People,dc=example,dc=com", 1, "ou=People,dc=example,dc=com"},
		{"uid=jdoe,ou=People,dc=example,dc=com", 2, "ou=People,dc=example,dc=com"},
		{"cn=x,ou=a,ou=b,dc=example,dc=com", 3, "ou=b,dc=example,dc=com"},
		{"dc=example,dc=com", 0, ""},
		{"dc=other,dc=com", -1, ""},
		{"dc=com", -1, ""},
		// Case differences in the suffix must not break the relationship.
		{"OU=People,DC=Example,DC=Com", 1, "OU=People,DC=Example,DC=Com"},
	}
	for _, c := range cases {
		if got := DepthUnder(c.child, base); got != c.depth {
			t.Errorf("DepthUnder(%q, %q) = %d, want %d", c.child, base, got, c.depth)
		}
		if got := AncestorUnder(c.child, base); got != c.ancestor {
			t.Errorf("AncestorUnder(%q, %q) = %q, want %q", c.child, base, got, c.ancestor)
		}
	}
}

// lldap answers a one-level search at the tree root with the whole subtree.
// Taking that at face value gives a flat, wrong tree with the real containers
// missing entirely.
func TestDirectChildrenRecoversSkippedContainers(t *testing.T) {
	base := "dc=example,dc=com"
	got := directChildren(base, []Entry{
		{DN: "uid=admin,ou=people,dc=example,dc=com", Subordinates: -1},
		{DN: "cn=lldap_admin,ou=groups,dc=example,dc=com", Subordinates: -1},
		{DN: "cn=lldap_password_manager,ou=groups,dc=example,dc=com", Subordinates: -1},
	})

	var dns []string
	for _, e := range got {
		dns = append(dns, e.DN)
		if !e.Synthesized {
			t.Errorf("%s should be marked synthesized", e.DN)
		}
		if e.HasSubordinates == nil || !*e.HasSubordinates {
			t.Errorf("%s was inferred from its own children, so it has some", e.DN)
		}
		if !isContainer(&e) {
			t.Errorf("%s should draw as a container", e.DN)
		}
	}
	want := []string{"ou=people,dc=example,dc=com", "ou=groups,dc=example,dc=com"}
	if !reflect.DeepEqual(dns, want) {
		t.Errorf("directChildren = %v, want %v", dns, want)
	}
}

func TestDirectChildrenIsANoOpOnAWellBehavedServer(t *testing.T) {
	base := "dc=example,dc=com"
	in := []Entry{
		{DN: "ou=People,dc=example,dc=com", Subordinates: -1},
		{DN: "ou=Groups,dc=example,dc=com", Subordinates: -1},
	}
	got := directChildren(base, in)
	if len(got) != 2 {
		t.Fatalf("directChildren = %v, want both entries untouched", got)
	}
	for _, e := range got {
		if e.Synthesized {
			t.Errorf("%s is a real entry and must not be marked synthesized", e.DN)
		}
	}
}

func TestDirectChildrenDropsStrangersAndPrefersRealEntries(t *testing.T) {
	base := "dc=example,dc=com"
	got := directChildren(base, []Entry{
		{DN: "dc=example,dc=com", Subordinates: -1},         // the node itself
		{DN: "ou=People,dc=other,dc=com", Subordinates: -1}, // a different tree
		{DN: "uid=jdoe,ou=People,dc=example,dc=com", Subordinates: -1},
		// The real container, returned after the entry that implied it.
		{DN: "ou=People,dc=example,dc=com", Subordinates: -1},
	})
	if len(got) != 1 {
		t.Fatalf("directChildren = %v, want just ou=People", got)
	}
	if got[0].Synthesized {
		t.Error("the real entry should win over the synthesised placeholder")
	}
	if !EqualDN(got[0].DN, "ou=People,dc=example,dc=com") {
		t.Errorf("got %q", got[0].DN)
	}
}

// A base-scope read that comes back with someone else's entry must not be shown
// under the requested DN's heading.
func TestPickEntryRefusesTheWrongEntry(t *testing.T) {
	entries := []Entry{
		{DN: "uid=admin,ou=people,dc=example,dc=com"},
		{DN: "cn=lldap_admin,ou=groups,dc=example,dc=com"},
	}
	if _, err := pickEntry("dc=example,dc=com", entries); err == nil {
		t.Fatal("no returned entry matches the requested DN, so this must fail")
	}

	got, err := pickEntry("cn=lldap_admin,ou=groups,dc=example,dc=com", entries)
	if err != nil {
		t.Fatalf("pickEntry: %v", err)
	}
	if !EqualDN(got.DN, "cn=lldap_admin,ou=groups,dc=example,dc=com") {
		t.Errorf("picked %q", got.DN)
	}

	// The root DSE has no DN worth matching on.
	if _, err := pickEntry("", []Entry{{DN: ""}}); err != nil {
		t.Errorf("root DSE should be accepted: %v", err)
	}
}
