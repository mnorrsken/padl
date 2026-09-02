package ldapx

import (
	"sort"
	"strings"
)

// RootDSE is the server's self-description, read from the empty DN. PADL uses
// it for two things: finding where the tree starts, and working out which
// vendor quirks apply.
type RootDSE struct {
	NamingContexts       []string
	DefaultNamingContext string // AD
	SchemaSubentry       string
	VendorName           string
	VendorVersion        string
	SupportedControl     []string
	SupportedExtension   []string
	SupportedSASL        []string
	SupportedLDAPVersion []string
	DSAName              string // eDirectory
	Raw                  *Entry
}

// rootDSEAttrs is what PADL asks for at the root. Most servers will not return
// these under "*", so they have to be named explicitly.
var rootDSEAttrs = []string{
	"namingContexts",
	"defaultNamingContext",
	"configurationNamingContext",
	"schemaNamingContext",
	"rootDomainNamingContext",
	"subschemaSubentry",
	"vendorName",
	"vendorVersion",
	"supportedControl",
	"supportedExtension",
	"supportedSASLMechanisms",
	"supportedLDAPVersion",
	"supportedCapabilities",
	"forestFunctionality",
	"domainFunctionality",
	"domainControllerFunctionality",
	"dsServiceName",
	"dsaName",
	// OpenLDAP publishes no vendorName; these two are how it names itself.
	"configContext",
	"structuralObjectClass",
}

// NewRootDSE builds a RootDSE from plain attribute values. Connect goes through
// parseRootDSE with a live entry; this is the same thing for callers that have
// the attributes already, and for tests that need a server description without
// a server.
func NewRootDSE(attrs map[string][]string) *RootDSE {
	e := &Entry{Subordinates: -1}
	for name, values := range attrs {
		vals := make([][]byte, len(values))
		for i, v := range values {
			vals[i] = []byte(v)
		}
		e.Attributes = append(e.Attributes, Attribute{Name: name, Values: vals})
	}
	return parseRootDSE(e)
}

func parseRootDSE(e *Entry) *RootDSE {
	r := &RootDSE{
		NamingContexts:       e.Get("namingContexts"),
		DefaultNamingContext: e.First("defaultNamingContext"),
		SchemaSubentry:       e.First("subschemaSubentry"),
		VendorName:           e.First("vendorName"),
		VendorVersion:        e.First("vendorVersion"),
		SupportedControl:     e.Get("supportedControl"),
		SupportedExtension:   e.Get("supportedExtension"),
		SupportedSASL:        e.Get("supportedSASLMechanisms"),
		SupportedLDAPVersion: e.Get("supportedLDAPVersion"),
		DSAName:              e.First("dsaName"),
		Raw:                  e,
	}
	return r
}

// Supports reports whether the server advertised a control OID, which is how
// PADL decides whether paged results are available.
func (r *RootDSE) Supports(oid string) bool {
	for _, c := range r.SupportedControl {
		if c == oid {
			return true
		}
	}
	return false
}

// hiddenADContexts are the AD partitions that are noise for someone browsing
// user and group data. They stay reachable through the "show all contexts"
// toggle.
func hiddenADContexts(r *RootDSE) map[string]bool {
	hidden := map[string]bool{}
	for _, a := range []string{"configurationNamingContext", "schemaNamingContext"} {
		if r.Raw != nil {
			for _, v := range r.Raw.Get(a) {
				hidden[strings.ToLower(v)] = true
			}
		}
	}
	return hidden
}

// Bases returns the DNs the tree should show as roots.
//
// The profile's explicit base DN always wins — that override exists precisely
// because eDirectory returns an empty namingContexts, which would otherwise
// leave the operator staring at an empty tree with no way forward. Measured on
// eDirectory 9.3.3: empty for an authenticated admin bind, not only an
// anonymous one.
func (r *RootDSE) Bases(override string, showAll bool) []string {
	if strings.TrimSpace(override) != "" {
		return []string{strings.TrimSpace(override)}
	}
	if r == nil {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	add := func(dn string) {
		dn = strings.TrimSpace(dn)
		if dn == "" || seen[strings.ToLower(dn)] {
			return
		}
		seen[strings.ToLower(dn)] = true
		out = append(out, dn)
	}

	// On AD the domain partition is what people actually want first.
	if r.DefaultNamingContext != "" {
		add(r.DefaultNamingContext)
	}

	rest := append([]string(nil), r.NamingContexts...)
	sort.SliceStable(rest, func(i, j int) bool {
		return strings.ToLower(rest[i]) < strings.ToLower(rest[j])
	})

	hidden := hiddenADContexts(r)
	for _, dn := range rest {
		if !showAll && hidden[strings.ToLower(dn)] {
			continue
		}
		add(dn)
	}
	return out
}
