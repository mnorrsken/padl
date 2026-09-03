package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// statusBar is the two bottom rows: one line of state or the last error, and
// one line of key hints.
type statusBar struct {
	*tview.Flex

	line *tview.TextView
	keys *tview.TextView

	// message is the current text, kept so the spinner can redraw it with a
	// new frame without the caller having to repeat itself.
	message string
	color   tcell.Color
	spinner string
}

func newStatusBar() *statusBar {
	s := &statusBar{
		Flex: tview.NewFlex().SetDirection(tview.FlexRow),
		line: tview.NewTextView().SetDynamicColors(true),
		// The hints are plain text and deliberately not tagged: they open with
		// the focused pane in square brackets, "[tree]" or "[object]", which a
		// tag parser reads as a colour it does not know and swallows whole. The
		// label had been invisible for exactly that reason.
		keys:  tview.NewTextView(),
		color: colorText,
	}
	s.line.SetBackgroundColor(colorBackground)
	s.keys.SetBackgroundColor(colorBackground)
	s.Flex.SetBackgroundColor(colorBackground)
	s.AddItem(s.line, 1, 0, false).AddItem(s.keys, 1, 0, false)
	return s
}

// setKeys replaces the hint line. Callers pass the bindings that are live for
// whatever currently has focus.
func (s *statusBar) setKeys(hints string) { s.keys.SetText(hints) }

func (s *statusBar) info(format string, args ...any)   { s.set(colorText, format, args...) }
func (s *statusBar) ok(format string, args ...any)     { s.set(colorOK, format, args...) }
func (s *statusBar) warn(format string, args ...any)   { s.set(colorWarn, format, args...) }
func (s *statusBar) errorf(format string, args ...any) { s.set(colorError, format, args...) }

func (s *statusBar) set(color tcell.Color, format string, args ...any) {
	s.message = fmt.Sprintf(format, args...)
	s.color = color
	s.render()
}

// setSpinner shows or clears the in-flight indicator without disturbing the
// message next to it.
func (s *statusBar) setSpinner(frame string) {
	s.spinner = frame
	s.render()
}

func (s *statusBar) render() {
	prefix := ""
	if s.spinner != "" {
		prefix = fmt.Sprintf("[%s]%s[-] ", tag(colorAccent), s.spinner)
	}
	s.line.SetText(fmt.Sprintf("%s[%s]%s[-]", prefix, tag(s.color), escape(s.message)))
}

// tag renders a colour as a tview colour tag. The terminal default has no name,
// and "-" is tview's spelling of "reset to default".
func tag(c tcell.Color) string {
	if c == tcell.ColorDefault {
		return "-"
	}
	return c.Name()
}
