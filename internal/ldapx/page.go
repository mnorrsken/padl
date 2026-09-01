package ldapx

import "strings"

// PageRequest asks for one page of results.
type PageRequest struct {
	// Size is how many entries to return. Zero means the profile's default.
	Size int
	// Cookie continues a previous page. Empty starts a fresh search.
	Cookie []byte
}

// Page is one page of search results.
type Page struct {
	Entries []Entry
	// Cookie continues from here. Empty means this was the last page.
	Cookie []byte
	// Truncated is set only when the server has more results and cannot be
	// asked for them — it does not support RFC 2696 paging. The difference
	// matters to the caller: More() can be offered, Truncated cannot.
	Truncated bool
}

// More reports whether another page can be fetched.
func (p *Page) More() bool { return p != nil && len(p.Cookie) > 0 }

// Next builds the request that continues from this page.
func (p *Page) Next(size int) PageRequest {
	return PageRequest{Size: size, Cookie: p.Cookie}
}

// Scope is a search scope, mirroring RFC 4511.
type Scope int

const (
	ScopeBase Scope = iota
	ScopeOneLevel
	ScopeSubtree
)

// String is the label the search bar shows.
func (s Scope) String() string {
	switch s {
	case ScopeBase:
		return "base"
	case ScopeOneLevel:
		return "one"
	default:
		return "sub"
	}
}

// Next cycles through the scopes, for a key that toggles them.
func (s Scope) Next() Scope {
	if s == ScopeSubtree {
		return ScopeBase
	}
	return s + 1
}

// Query is a search the user asked for.
type Query struct {
	BaseDN string
	Scope  Scope
	Filter string
	// Attributes to fetch; nil means the tree-row minimum.
	Attributes []string
	// Label is what to call this search on screen. A quick search builds a
	// filter far too long to use as a title, so it carries the words the user
	// typed instead. Empty means use Filter.
	Label string
}

// Title is the short name for this search.
func (q Query) Title() string {
	if strings.TrimSpace(q.Label) != "" {
		return q.Label
	}
	return q.Filter
}
