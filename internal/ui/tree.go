package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/ldapx"
)

// nodeKind separates the three sorts of row the tree holds.
type nodeKind int

const (
	nodeEntry       nodeKind = iota // a real directory entry
	nodeBase                        // a naming context, i.e. a tree root
	nodeMore                        // the synthetic "N more" row under a truncated container
	nodePlaceholder                 // "loading…" / "empty", never selectable as an entry
)

// node is what hangs off every TreeNode's reference.
type node struct {
	kind nodeKind
	dn   string

	// entry is the tree-level view of the entry: object classes and the
	// subordinate hints. It is not the full attribute set — that is fetched
	// separately when the object pane needs it.
	entry *ldapx.Entry

	// loaded is true once children have been fetched, so re-expanding a node
	// does not re-query. `r` clears it.
	loaded bool
	// loading guards against a second fetch while one is in flight, which is
	// easy to trigger by holding down the expand key.
	loading bool
	// truncated is true when the server had more children than were shown.
	truncated bool
	// childCount is how many children were actually loaded.
	childCount int
}

// tree is the left pane.
type tree struct {
	*tview.TreeView

	root *tview.TreeNode

	// expand is called when a node needs its children; the app supplies it so
	// the tree itself never knows about connections or contexts.
	expand func(n *tview.TreeNode, ref *node)
	// selected is called when the highlighted row changes.
	selected func(ref *node)
}

func newTree() *tree {
	t := &tree{TreeView: tview.NewTreeView()}
	t.root = tview.NewTreeNode("").SetSelectable(false)
	t.SetRoot(t.root).
		SetTopLevel(1). // the root is a container for the bases, not a row
		SetGraphics(true).
		SetGraphicsColor(colorDim)
	t.SetBorder(true).
		SetTitle(" Directory ").
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)

	t.SetChangedFunc(func(n *tview.TreeNode) {
		if t.selected != nil {
			t.selected(refOf(n))
		}
	})
	t.SetSelectedFunc(func(n *tview.TreeNode) { t.toggle(n) })
	return t
}

// newNode builds a tree row with a readable highlight.
//
// tview derives a node's selected-row style from SetColor: the node colour
// becomes the highlight background and the theme's background colour becomes
// its foreground. For a node left at the terminal default that lands dark text
// on a dark background — invisible. Setting the style explicitly, after
// SetColor, is what keeps every row legible, and it matches the object pane's
// highlight.
func newNode(text string, color tcell.Color) *tview.TreeNode {
	n := tview.NewTreeNode(text).SetColor(color)
	n.SetSelectedTextStyle(tcell.StyleDefault.
		Background(colorSelected).
		Foreground(tcell.ColorWhite).
		Attributes(tcell.AttrBold))
	return n
}

// refOf pulls the node payload off a TreeNode, or nil for rows that have none.
func refOf(n *tview.TreeNode) *node {
	if n == nil {
		return nil
	}
	ref, _ := n.GetReference().(*node)
	return ref
}

// isLeaf reports whether a node is known to have no children, either because
// the server said so or because expanding it already came back empty. Leaves
// are never queried again and never open.
func isLeaf(n *tview.TreeNode, ref *node) bool {
	if ref.loaded {
		return len(n.GetChildren()) == 0
	}
	e := ref.entry
	return e != nil && e.HasSubordinates != nil && !*e.HasSubordinates
}

// toggle expands or collapses a row, fetching children the first time.
func (t *tree) toggle(n *tview.TreeNode) {
	ref := refOf(n)
	if ref == nil || ref.kind == nodePlaceholder {
		return
	}
	if ref.kind == nodeMore {
		// "N more" is informational in this milestone; paging past it arrives
		// with the search work.
		return
	}
	if isLeaf(n, ref) {
		return
	}
	if !ref.loaded {
		if ref.loading || t.expand == nil {
			return
		}
		t.expand(n, ref)
		return
	}
	n.SetExpanded(!n.IsExpanded())
}

// reset clears the tree back to a set of naming contexts.
func (t *tree) reset(bases []string, title string) {
	t.root.ClearChildren()
	t.SetTitle(fmt.Sprintf(" %s ", tview.Escape(title)))
	for _, dn := range bases {
		n := newNode(tview.Escape(fmt.Sprintf("%s %s", iconRoot, dn)), colorAccent).
			SetReference(&node{kind: nodeBase, dn: dn}).
			SetSelectable(true)
		t.root.AddChild(n)
	}
	if len(t.root.GetChildren()) > 0 {
		t.SetCurrentNode(t.root.GetChildren()[0])
	} else {
		t.SetCurrentNode(t.root)
	}
}

// clear empties the tree, for the disconnected state.
func (t *tree) clear(title string) {
	t.root.ClearChildren()
	t.SetTitle(fmt.Sprintf(" %s ", tview.Escape(title)))
	t.SetCurrentNode(t.root)
}

// markLoading puts a placeholder under a node so an expand that is waiting on
// the network looks like it is doing something.
func (t *tree) markLoading(n *tview.TreeNode) {
	n.ClearChildren()
	n.AddChild(newNode("loading…", colorDim).
		SetReference(&node{kind: nodePlaceholder}).
		SetSelectable(false))
	n.SetExpanded(true)
}

// setChildren replaces a node's children with fetched entries.
//
// An entry the server said nothing about is drawn as expandable; if it turns
// out to be empty, this is where it collapses to a leaf. That is the fallback
// for servers — eDirectory among them — that do not publish hasSubordinates.
func (t *tree) setChildren(n *tview.TreeNode, ref *node, entries []ldapx.Entry, truncated bool) {
	n.ClearChildren()
	ref.loaded = true
	ref.loading = false
	ref.truncated = truncated
	ref.childCount = len(entries)

	for i := range entries {
		e := entries[i]
		child := &node{kind: nodeEntry, dn: e.DN, entry: &e}
		n.AddChild(newEntryNode(child))
	}

	if truncated {
		n.AddChild(newNode(
			fmt.Sprintf("%s more than %d entries — narrow with a search", iconMore, len(entries)),
			colorWarn).
			SetReference(&node{kind: nodeMore, dn: ref.dn}).
			SetSelectable(true))
	}

	// A node that turns out to have no children just becomes a leaf. Hanging an
	// "(empty)" row under every user and group would be noise on every screen,
	// and the absence of children already says it.
	n.SetExpanded(len(n.GetChildren()) > 0)
}

// failLoad reverts a node after a failed expand so the user can retry it.
func (t *tree) failLoad(n *tview.TreeNode, ref *node) {
	ref.loading = false
	ref.loaded = false
	n.ClearChildren()
	n.SetExpanded(false)
}

func newEntryNode(ref *node) *tview.TreeNode {
	n := newNode(entryLabel(ref.entry), entryColor(ref.entry)).
		SetReference(ref).
		SetSelectable(true)
	// Anything not known to be childless is drawn collapsed-but-expandable;
	// the first expand settles it either way.
	n.SetExpanded(false)
	return n
}

// entryLabel builds a tree row.
//
// The whole thing is escaped: tview reads square brackets as style tags, so an
// unescaped "[u]" icon is swallowed silently — and so is any RDN whose value
// happens to contain brackets, which is legal in a DN.
func entryLabel(e *ldapx.Entry) string {
	icon := iconOther
	switch ldapx.KindOf(e) {
	case ldapx.KindContainer:
		icon = iconContainer
	case ldapx.KindPerson:
		icon = iconPerson
	case ldapx.KindGroup:
		icon = iconGroup
	case ldapx.KindComputer:
		icon = iconComputer
	}
	label := fmt.Sprintf("%s %s", icon, e.RDN())
	if e.Subordinates > 0 {
		label += fmt.Sprintf(" (%d)", e.Subordinates)
	}
	return tview.Escape(label)
}

func entryColor(e *ldapx.Entry) tcell.Color {
	if ldapx.KindOf(e) == ldapx.KindContainer {
		return colorAccent
	}
	return colorText
}

// expandCurrent opens the highlighted node, loading its children on the first
// open.
//
// tview's TreeView maps Left and Right to plain up/down movement, so expand and
// collapse have to be wired here rather than inherited.
func (t *tree) expandCurrent() {
	n := t.GetCurrentNode()
	if n == nil {
		return
	}
	ref := refOf(n)
	if ref == nil || ref.kind == nodePlaceholder || ref.kind == nodeMore {
		return
	}
	if isLeaf(n, ref) {
		return
	}
	if !ref.loaded {
		if ref.loading || t.expand == nil {
			return
		}
		t.expand(n, ref)
		return
	}
	n.SetExpanded(true)
}

// collapseCurrent closes the highlighted node. It reports false when the node
// was already closed, which is the caller's cue to step up to the parent
// instead — the movement people expect from a file tree.
func (t *tree) collapseCurrent() bool {
	n := t.GetCurrentNode()
	if n == nil {
		return false
	}
	if !n.IsExpanded() || len(n.GetChildren()) == 0 {
		return false
	}
	n.SetExpanded(false)
	return true
}

// find locates the node holding a DN, or nil. Placeholder rows are skipped so a
// half-loaded branch cannot be mistaken for a hit.
func (t *tree) find(dn string) *tview.TreeNode {
	var found *tview.TreeNode
	t.root.Walk(func(n, _ *tview.TreeNode) bool {
		if found != nil {
			return false
		}
		ref := refOf(n)
		if ref == nil || ref.kind == nodePlaceholder || ref.kind == nodeMore {
			return true
		}
		if ldapx.EqualDN(ref.dn, dn) {
			found = n
			return false
		}
		return true
	})
	return found
}

// bases are the naming contexts currently at the top of the tree.
func (t *tree) bases() []string {
	children := t.root.GetChildren()
	out := make([]string, 0, len(children))
	for _, n := range children {
		if ref := refOf(n); ref != nil && ref.kind == nodeBase {
			out = append(out, ref.dn)
		}
	}
	return out
}

// currentDN is the DN under the cursor, or "" when the cursor is not on an
// entry.
func (t *tree) currentDN() string {
	ref := refOf(t.GetCurrentNode())
	if ref == nil || ref.kind == nodePlaceholder {
		return ""
	}
	return ref.dn
}
