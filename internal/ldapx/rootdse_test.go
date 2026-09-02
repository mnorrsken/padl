package ldapx

import (
	"reflect"
	"testing"
)

func rootEntry(pairs map[string][]string) *Entry {
	e := &Entry{DN: "", Subordinates: -1}
	for name, values := range pairs {
		vals := make([][]byte, len(values))
		for i, v := range values {
			vals[i] = []byte(v)
		}
		e.Attributes = append(e.Attributes, Attribute{Name: name, Values: vals})
	}
	return e
}

func TestDetectVendor(t *testing.T) {
	cases := []struct {
		name string
		attr map[string][]string
		want Vendor
	}{
		{
			name: "active directory",
			attr: map[string][]string{
				"defaultNamingContext": {"DC=corp,DC=example,DC=com"},
				"forestFunctionality":  {"7"},
				"dsServiceName":        {"CN=NTDS Settings,..."},
			},
			want: VendorActiveDirectory,
		},
		{
			name: "edirectory by vendor version",
			attr: map[string][]string{
				"vendorName":    {"NetIQ Corporation"},
				"vendorVersion": {"LDAP Agent for NetIQ eDirectory 9.2.4"},
			},
			want: VendorEDirectory,
		},
		{
			name: "openldap",
			attr: map[string][]string{"vendorName": {"OpenLDAP Foundation"}},
			want: VendorOpenLDAP,
		},
		{
			name: "389ds",
			attr: map[string][]string{"vendorName": {"389 Project"}},
			want: Vendor389DS,
		},
		{
			name: "plain ldapv3 stays generic rather than guessing",
			attr: map[string][]string{"namingContexts": {"dc=example,dc=com"}},
			want: VendorGeneric,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DetectVendor(parseRootDSE(rootEntry(c.attr))); got != c.want {
				t.Errorf("DetectVendor = %v, want %v", got, c.want)
			}
		})
	}
	if got := DetectVendor(nil); got != VendorGeneric {
		t.Errorf("DetectVendor(nil) = %v, want VendorGeneric", got)
	}
}

func TestBasesPrefersDefaultNamingContextAndHidesADPartitions(t *testing.T) {
	r := parseRootDSE(rootEntry(map[string][]string{
		"defaultNamingContext":       {"DC=corp,DC=example,DC=com"},
		"configurationNamingContext": {"CN=Configuration,DC=corp,DC=example,DC=com"},
		"schemaNamingContext":        {"CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com"},
		"forestFunctionality":        {"7"},
		"namingContexts": {
			"CN=Configuration,DC=corp,DC=example,DC=com",
			"DC=corp,DC=example,DC=com",
			"CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com",
			"DC=DomainDnsZones,DC=corp,DC=example,DC=com",
		},
	}))

	got := r.Bases("", false)
	want := []string{
		"DC=corp,DC=example,DC=com",
		"DC=DomainDnsZones,DC=corp,DC=example,DC=com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Bases(hidden) = %v, want %v", got, want)
	}

	if all := r.Bases("", true); len(all) != 4 {
		t.Errorf("Bases(showAll) = %v, want all four partitions", all)
	}
}

// The override exists for eDirectory, which publishes an empty namingContexts
// however you bind; without it the operator gets an empty tree and no way
// forward.
func TestBasesOverrideWinsAndRescuesEmptyRootDSE(t *testing.T) {
	r := parseRootDSE(rootEntry(map[string][]string{
		"namingContexts": {"dc=example,dc=com"},
	}))
	if got := r.Bases("o=acme", false); !reflect.DeepEqual(got, []string{"o=acme"}) {
		t.Errorf("override ignored, got %v", got)
	}

	empty := parseRootDSE(rootEntry(nil))
	if got := empty.Bases("", false); len(got) != 0 {
		t.Errorf("empty root DSE with no override = %v, want nothing", got)
	}
	if got := empty.Bases("  o=acme  ", false); !reflect.DeepEqual(got, []string{"o=acme"}) {
		t.Errorf("override on empty root DSE = %v", got)
	}
}

func TestBasesDeduplicates(t *testing.T) {
	r := parseRootDSE(rootEntry(map[string][]string{
		"defaultNamingContext": {"DC=corp,DC=example,DC=com"},
		"namingContexts":       {"dc=corp,dc=example,dc=com"}, // same DN, different case
	}))
	if got := r.Bases("", true); len(got) != 1 {
		t.Errorf("Bases = %v, want the DN listed once", got)
	}
}

func TestSupports(t *testing.T) {
	r := parseRootDSE(rootEntry(map[string][]string{
		"supportedControl": {OIDPagedResults, "1.2.840.113556.1.4.801"},
	}))
	if !r.Supports(OIDPagedResults) {
		t.Error("paged results should be reported as supported")
	}
	if r.Supports("9.9.9") {
		t.Error("unadvertised control should not be reported as supported")
	}
}

// OpenLDAP publishes no vendorName, so it has to be recognised by the root DSE
// attributes it does expose. This is what a live 2.4 server actually returns.
func TestDetectOpenLDAPWithoutVendorName(t *testing.T) {
	r := parseRootDSE(rootEntry(map[string][]string{
		"structuralObjectClass": {"OpenLDAProotDSE"},
		"configContext":         {"cn=config"},
		"namingContexts":        {"dc=example,dc=com"},
	}))
	if got := DetectVendor(r); got != VendorOpenLDAP {
		t.Errorf("DetectVendor = %v, want OpenLDAP", got)
	}

	// A vendor that names itself must still win over the configContext hint.
	ad := parseRootDSE(rootEntry(map[string][]string{
		"defaultNamingContext": {"DC=corp,DC=example,DC=com"},
		"forestFunctionality":  {"7"},
		"configContext":        {"cn=config"},
	}))
	if got := DetectVendor(ad); got != VendorActiveDirectory {
		t.Errorf("DetectVendor = %v, want Active Directory", got)
	}
}

// lldap publishes defaultNamingContext and a faked isGlobalCatalogReady, which
// is most of what the Active Directory heuristic looks for — so its own vendor
// name has to be checked first.
func TestDetectLLDAPIsNotMistakenForActiveDirectory(t *testing.T) {
	r := parseRootDSE(rootEntry(map[string][]string{
		"vendorName":           {"LLDAP"},
		"vendorVersion":        {"lldap_0.1.1"},
		"defaultNamingContext": {"dc=example,dc=com"},
		"namingContexts":       {"dc=example,dc=com"},
		"isGlobalCatalogReady": {"false"},
		"subschemaSubentry":    {"cn=Subschema"},
	}))
	if got := DetectVendor(r); got != VendorLLDAP {
		t.Errorf("DetectVendor = %v, want lldap", got)
	}
}
