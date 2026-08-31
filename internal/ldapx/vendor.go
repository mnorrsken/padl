package ldapx

import "strings"

// Vendor is the directory implementation PADL is talking to. It is deliberately
// consulted in only three places — which naming contexts to surface, how to
// render a few binary attributes, and whether paged results exist — so the
// generic RFC 4511 path stays the one that actually gets exercised.
type Vendor int

const (
	// VendorGeneric is plain standards-compliant LDAPv3.
	VendorGeneric Vendor = iota
	VendorActiveDirectory
	VendorEDirectory
	VendorOpenLDAP
	Vendor389DS
	VendorLLDAP
)

// String is the label shown on the status bar.
func (v Vendor) String() string {
	switch v {
	case VendorActiveDirectory:
		return "Active Directory"
	case VendorEDirectory:
		return "eDirectory"
	case VendorOpenLDAP:
		return "OpenLDAP"
	case Vendor389DS:
		return "389 Directory Server"
	case VendorLLDAP:
		return "lldap"
	default:
		return "LDAPv3"
	}
}

// DetectVendor identifies the server from its root DSE.
//
// Active Directory is recognised by the pair of attributes only it publishes;
// eDirectory by its vendor string or the dsaName it exposes. Everything else
// falls through to the generic path on purpose — a wrong guess here would apply
// the wrong value formatting, which is worse than no guess at all.
func DetectVendor(r *RootDSE) Vendor {
	if r == nil {
		return VendorGeneric
	}
	name := strings.ToLower(r.VendorName)
	version := strings.ToLower(r.VendorVersion)

	// lldap names itself plainly, and has to be checked before the Active
	// Directory heuristics: it publishes defaultNamingContext and a faked
	// isGlobalCatalogReady, which is most of what AD detection looks for.
	if strings.Contains(name, "lldap") || strings.Contains(version, "lldap") {
		return VendorLLDAP
	}

	if r.Raw != nil {
		hasForest := len(r.Raw.Get("forestFunctionality")) > 0
		hasDefaultNC := r.DefaultNamingContext != ""
		if hasForest && hasDefaultNC {
			return VendorActiveDirectory
		}
		if len(r.Raw.Get("dsServiceName")) > 0 && hasDefaultNC {
			return VendorActiveDirectory
		}
	}

	// OpenLDAP publishes no vendorName at all, so it has to be recognised by
	// the root DSE attributes only it exposes.
	if r.Raw != nil {
		for _, v := range r.Raw.Get("structuralObjectClass") {
			if strings.EqualFold(v, "OpenLDAProotDSE") {
				return VendorOpenLDAP
			}
		}
		if len(r.Raw.Get("configContext")) > 0 && name == "" {
			return VendorOpenLDAP
		}
	}

	switch {
	case strings.Contains(version, "edirectory"),
		strings.Contains(name, "netiq"),
		strings.Contains(name, "novell"),
		r.DSAName != "" && strings.Contains(name, "micro focus"):
		return VendorEDirectory
	case strings.Contains(name, "389"), strings.Contains(version, "389-directory"),
		strings.Contains(name, "red hat"):
		return Vendor389DS
	case strings.Contains(name, "openldap"), strings.Contains(version, "openldap"):
		return VendorOpenLDAP
	}
	return VendorGeneric
}
