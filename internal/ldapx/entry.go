// Package ldapx wraps go-ldap in the small, cancellable surface PADL's UI
// needs. Nothing above this package imports go-ldap directly, which is what
// lets the UI be tested against a fake directory.
package ldapx

import (
	"context"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Attribute is one attribute of an entry. Values are kept as raw bytes because
// plenty of LDAP attributes (objectGUID, objectSid, certificates, photos) are
// not text at all; rendering is attr.go's job.
type Attribute struct {
	Name        string
	Values      [][]byte
	Operational bool
}

// Strings renders the values as plain strings, for the cases where the caller
// already knows the attribute is text.
func (a Attribute) Strings() []string {
	out := make([]string, len(a.Values))
	for i, v := range a.Values {
		out[i] = string(v)
	}
	return out
}

// Entry is a directory entry.
type Entry struct {
	DN         string
	Attributes []Attribute

	// HasSubordinates is the server's answer to "does this entry have
	// children", or nil when it did not say. eDirectory in particular often
	// leaves this out, so the tree has to fall back to trying a one-level
	// search and collapsing the node if nothing comes back.
	HasSubordinates *bool
	// Subordinates is numSubordinates, or -1 when the server did not say.
	Subordinates int

	// Synthesized marks a node PADL inferred rather than read: an intermediate
	// container that a server skipped over when answering a one-level search.
	// It has children by construction, so it is drawn as a container even
	// though its own attributes have not been fetched.
	Synthesized bool
}

// Get returns the values of an attribute as strings, case-insensitively.
func (e *Entry) Get(name string) []string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Strings()
		}
	}
	return nil
}

// First returns the first value of an attribute, or "".
func (e *Entry) First(name string) string {
	if v := e.Get(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Classes returns the entry's objectClass values.
func (e *Entry) Classes() []string { return e.Get("objectClass") }

// RDN is the leftmost component of the DN, which is what the tree shows.
func (e *Entry) RDN() string { return RDN(e.DN) }

// RDN returns the leftmost component of a DN, honouring backslash escapes so a
// value containing a literal comma is not split in half.
func RDN(dn string) string {
	if parts := SplitDN(dn); len(parts) > 0 {
		return parts[0]
	}
	return dn
}

// SplitDN breaks a DN into its components, honouring backslash escapes so a
// value containing a literal comma is not split in half.
func SplitDN(dn string) []string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil
	}
	var (
		parts []string
		start int
		esc   bool
	)
	for i := 0; i < len(dn); i++ {
		switch {
		case esc:
			esc = false
		case dn[i] == '\\':
			esc = true
		case dn[i] == ',':
			parts = append(parts, strings.TrimSpace(dn[start:i]))
			start = i + 1
		}
	}
	return append(parts, strings.TrimSpace(dn[start:]))
}

// EqualDN compares two DNs. It is deliberately shallow — component-wise and
// case-insensitive — which is enough to tell entries apart without taking on
// full RFC 4518 string preparation.
func EqualDN(a, b string) bool {
	pa, pb := SplitDN(a), SplitDN(b)
	if len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		if !strings.EqualFold(pa[i], pb[i]) {
			return false
		}
	}
	return true
}

// DepthUnder reports how many DN components separate child from parent: 1 for a
// direct child, 2 for a grandchild, 0 when child is parent itself, and -1 when
// child does not sit under parent at all.
func DepthUnder(child, parent string) int {
	pc, pp := SplitDN(child), SplitDN(parent)
	if len(pc) < len(pp) {
		return -1
	}
	offset := len(pc) - len(pp)
	for i := range pp {
		if !strings.EqualFold(pc[offset+i], pp[i]) {
			return -1
		}
	}
	return offset
}

// AncestorUnder returns the ancestor of child that is a direct child of parent.
// It is how a stray deep entry is turned back into the tree node it belongs
// under. The empty string means child does not sit under parent.
func AncestorUnder(child, parent string) string {
	depth := DepthUnder(child, parent)
	if depth <= 0 {
		return ""
	}
	pc := SplitDN(child)
	return strings.Join(pc[depth-1:], ",")
}

// IsDN reports whether s parses as a distinguished name.
//
// On its own this is a weak test — "x=" and "http://example.com/a=b" both pass —
// so callers deciding whether a value is a followable reference should use
// IsDNUnder instead, which also requires the DN to live in the tree.
func IsDN(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, err := ldap.ParseDN(s)
	return err == nil
}

// IsDNUnder reports whether value is a DN sitting at or under one of bases.
//
// This is what makes attribute values safely clickable: plenty of ordinary text
// parses as a DN by accident, but almost none of it also lands inside a naming
// context the server published.
func IsDNUnder(value string, bases []string) bool {
	return BestBase(value, bases) != ""
}

// BestBase returns the most specific of bases that contains dn, or "" when none
// does. The most specific wins so a DN inside a nested partition is walked from
// the closest root rather than the widest one.
func BestBase(dn string, bases []string) string {
	if !IsDN(dn) {
		return ""
	}
	best, bestLen := "", -1
	for _, b := range bases {
		if DepthUnder(dn, b) < 0 {
			continue
		}
		if n := len(SplitDN(b)); n > bestLen {
			best, bestLen = b, n
		}
	}
	return best
}

// PathFrom returns the chain of DNs from base down to dn inclusive, which is
// the sequence of tree nodes that has to be expanded to reveal dn. It returns
// nil when dn does not sit under base.
func PathFrom(base, dn string) []string {
	depth := DepthUnder(dn, base)
	if depth < 0 {
		return nil
	}
	parts := SplitDN(dn)
	path := make([]string, 0, depth+1)
	path = append(path, base)
	for i := depth - 1; i >= 0; i-- {
		path = append(path, strings.Join(parts[i:], ","))
	}
	return path
}

// SortEntries orders children the way a person expects to read them:
// containers first, then everything else, each group by RDN case-insensitively.
func SortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		ci, cj := isContainer(&entries[i]), isContainer(&entries[j])
		if ci != cj {
			return ci
		}
		return strings.ToLower(entries[i].RDN()) < strings.ToLower(entries[j].RDN())
	})
}

// containerClasses are the object classes PADL treats as structural containers
// for sorting and icon purposes.
var containerClasses = map[string]bool{
	"organizationalunit": true,
	"organization":       true,
	"container":          true,
	"domain":             true,
	"domaindns":          true,
	"country":            true,
	"locality":           true,
	"builtindomain":      true,
	"treeroot":           true, // eDirectory
	"partition":          true, // eDirectory
}

func isContainer(e *Entry) bool {
	if e.Synthesized {
		return true
	}
	for _, c := range e.Classes() {
		if containerClasses[strings.ToLower(c)] {
			return true
		}
	}
	return false
}

// Kind is a coarse classification of an entry, used to pick its tree icon.
type Kind int

const (
	KindOther Kind = iota
	KindContainer
	KindPerson
	KindGroup
	KindComputer
)

var kindByClass = map[string]Kind{
	"person":               KindPerson,
	"organizationalperson": KindPerson,
	"inetorgperson":        KindPerson,
	"user":                 KindPerson,
	"posixaccount":         KindPerson,
	"group":                KindGroup,
	"groupofnames":         KindGroup,
	"groupofuniquenames":   KindGroup,
	"posixgroup":           KindGroup,
	"groupofentries":       KindGroup,
	"computer":             KindComputer,
	"device":               KindComputer,
	"ipnetworkelement":     KindComputer,
}

// KindOf classifies an entry by its object classes. The more specific answer
// wins, so a user object inside an OU still reads as a person.
func KindOf(e *Entry) Kind {
	for _, c := range e.Classes() {
		if k, ok := kindByClass[strings.ToLower(c)]; ok {
			return k
		}
	}
	if isContainer(e) {
		return KindContainer
	}
	return KindOther
}

// Directory is everything the UI is allowed to ask of a server. Keeping it this
// narrow is what makes the UI testable against a fake.
type Directory interface {
	// RootDSE returns the server's root DSE, already parsed.
	RootDSE(ctx context.Context) (*RootDSE, error)
	// Children lists the immediate subordinates of dn, one page at a time.
	Children(ctx context.Context, dn string, req PageRequest) (*Page, error)
	// Search runs an arbitrary query, one page at a time.
	Search(ctx context.Context, q Query, req PageRequest) (*Page, error)
	// Entry reads a single entry. When operational is true the server's
	// operational attributes are fetched as well.
	Entry(ctx context.Context, dn string, operational bool) (*Entry, error)
	// Close releases the connection.
	Close() error
}
