package ldapx

import (
	"fmt"
	"strings"
)

// Quick search turns bare words into an LDAP filter: "mar nor" becomes every
// term ANDed together, each term ORed across the attributes people actually
// search by, with a trailing wildcard for prefix matching.
//
//	(&(|(cn=mar*)(sn=mar*)…)(|(cn=nor*)(sn=nor*)…))
//
// The attribute list is per-vendor rather than one broad set, because a broad
// one does not work. RFC 4511 says a filter naming an unknown attribute is
// Undefined and simply fails to match, and OpenLDAP behaves that way — but
// lldap does not: a substring match on sn, givenName or memberOf there returns
// nothing *and takes the whole OR down with it*, so `(|(cn=adm*)(sn=adm*))`
// finds nobody even though `(cn=adm*)` alone matches. Sending every server the
// same generous list would quietly return "no matches" on a server that has the
// entry. Hence one list per vendor, each holding only what that server can
// actually substring-match.

// genericQuickAttributes is the RFC 4519 / inetOrgPerson set: what a
// standards-compliant server can be expected to know.
var genericQuickAttributes = []string{
	"cn", "sn", "givenName", "displayName", "uid", "mail", "ou", "o", "description",
}

// adQuickAttributes is Active Directory's. sAMAccountName and userPrincipalName
// are how people actually refer to accounts there. uid is deliberately absent:
// it only exists once the RFC 2307 schema extension is installed, and AD is the
// server least forgiving of an attribute it does not know.
var adQuickAttributes = []string{
	"sAMAccountName", "userPrincipalName", "cn", "name", "displayName",
	"givenName", "sn", "mail", "proxyAddresses", "description", "ou",
}

// edirQuickAttributes is eDirectory's, which carries fullName alongside the
// usual pieces.
var edirQuickAttributes = []string{
	"cn", "uid", "fullName", "givenName", "sn", "mail", "ou", "o", "description",
}

// lldapQuickAttributes is deliberately short. Verified against lldap 0.1.1: a
// substring filter on sn, givenName or memberOf matches nothing there and
// poisons any OR it appears in, so those are left out even though lldap stores
// them. These four cover users and groups.
var lldapQuickAttributes = []string{
	"uid", "cn", "mail", "displayName",
}

// QuickSearchAttributes returns the attributes a bare-word search looks in on
// this kind of server.
func QuickSearchAttributes(v Vendor) []string {
	switch v {
	case VendorActiveDirectory:
		return adQuickAttributes
	case VendorEDirectory:
		return edirQuickAttributes
	case VendorLLDAP:
		return lldapQuickAttributes
	default:
		return genericQuickAttributes
	}
}

// IsRawFilter reports whether input should be taken as an LDAP filter as typed
// rather than as search terms. A leading "(" is the signal: it is what every
// filter starts with, and no bare search term sensibly does.
func IsRawFilter(input string) bool {
	return strings.HasPrefix(strings.TrimSpace(input), "(")
}

// QuickFilter builds a filter from bare search terms. Input that already looks
// like a filter is returned untouched, so the search bar can hand it either
// kind of thing.
//
// It returns "" for input with no usable terms; the caller decides what that
// means.
func QuickFilter(input string, v Vendor) string {
	if IsRawFilter(input) {
		return strings.TrimSpace(input)
	}
	return QuickFilterFor(strings.Fields(input), QuickSearchAttributes(v))
}

// QuickFilterFor builds the filter for explicit terms and attributes.
func QuickFilterFor(terms, attributes []string) string {
	if len(attributes) == 0 {
		return ""
	}

	var clauses []string
	for _, term := range terms {
		value := wildcard(term)
		if value == "" {
			continue
		}
		var b strings.Builder
		b.WriteString("(|")
		for _, attr := range attributes {
			fmt.Fprintf(&b, "(%s=%s)", attr, value)
		}
		b.WriteString(")")
		clauses = append(clauses, b.String())
	}

	switch len(clauses) {
	case 0:
		return ""
	case 1:
		// One term needs no conjunction; "(&(|…))" would only be noise in the
		// preview the user reads.
		return clauses[0]
	default:
		return "(&" + strings.Join(clauses, "") + ")"
	}
}

// wildcard escapes a term and gives it a trailing "*" so it matches by prefix.
// A term the user already wildcarded is left as they wrote it.
func wildcard(term string) string {
	escaped := escapeTerm(term)
	if escaped == "" {
		return ""
	}
	if strings.Contains(escaped, "*") {
		return escaped
	}
	return escaped + "*"
}

// escapeTerm escapes a search term for use as an RFC 4515 assertion value,
// leaving "*" alone so a wildcard the user typed keeps working.
func escapeTerm(term string) string {
	var b strings.Builder
	for i := 0; i < len(term); i++ {
		c := term[i]
		switch c {
		case '*':
			// Intentionally not escaped: the whole point is prefix matching,
			// and a user who types one means it.
			b.WriteByte(c)
		case '(', ')', '\\', 0x00:
			fmt.Fprintf(&b, "\\%02x", c)
		default:
			// Control bytes have no business in a filter unescaped; everything
			// else, UTF-8 included, RFC 4515 allows literally.
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, "\\%02x", c)
				continue
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}
