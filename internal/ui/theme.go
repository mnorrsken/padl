// Package ui is PADL's terminal interface. It talks to a directory only
// through ldapx.Directory, which is what lets the whole thing be driven from a
// test against a fake server.
package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/ldapx"
)

// The palette leaves the background at the terminal default so PADL inherits
// whatever theme the user already has, light or dark, instead of stamping its
// own dark rectangle over it.
var (
	colorBackground = tcell.ColorDefault
	colorText       = tcell.ColorDefault
	colorBorder     = tcell.ColorGray
	colorTitle      = tcell.ColorTeal
	colorAccent     = tcell.ColorTeal
	colorDim        = tcell.ColorGray
	colorAttrName   = tcell.ColorTeal
	colorBinary     = tcell.ColorPurple
	colorLink       = tcell.ColorTeal
	colorError      = tcell.ColorRed
	colorWarn       = tcell.ColorYellow
	colorOK         = tcell.ColorGreen
	colorSelected   = tcell.ColorBlue
)

// icons mark what a tree row is. They are ASCII on purpose: a directory tree is
// the kind of thing that gets read over ssh from a console with no font.
const (
	iconContainer = "[+]"
	iconPerson    = "[u]"
	iconGroup     = "[g]"
	iconComputer  = "[c]"
	iconOther     = " . "
	iconRoot      = "[/]"
	iconMore      = "..."
)

func styleBorder(color tcell.Color) tcell.Style {
	return tcell.StyleDefault.Foreground(color).Background(colorBackground)
}

// escape prepares a string for drawing. Everything on screen goes through it,
// whether it came from the user or from the directory.
//
// Two things, one call. tview reads square brackets as style tags, so an
// unescaped "[u]" is swallowed silently — that is the one that bites daily.
// SafeText handles the other: a DN is server-supplied text, and a directory is
// free to put an escape sequence in one. tview's own draw loop already discards
// control runes, so this does not fix a live hole; it means PADL decides what
// reaches the terminal rather than inheriting that from tview.
func escape(s string) string {
	return tview.Escape(ldapx.SafeText(s))
}
