package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/ldapx"
)

// searchBar is the line that appears on `/`: the filter, the base it runs
// against, and the scope.
type searchBar struct {
	*tview.Flex

	input *tview.InputField
	info  *tview.TextView

	base  string
	scope ldapx.Scope

	// history is this session's filters, newest last. Up and Down walk it.
	history []string
	pos     int
	// draft holds what was typed before walking into history, so coming back
	// out restores it rather than losing it.
	draft string

	run    func(q ldapx.Query)
	cancel func()
}

func newSearchBar() *searchBar {
	s := &searchBar{
		Flex:  tview.NewFlex().SetDirection(tview.FlexRow),
		input: tview.NewInputField(),
		info:  tview.NewTextView().SetDynamicColors(true),
		scope: ldapx.ScopeSubtree,
	}
	s.info.SetBackgroundColor(colorBackground)
	s.Flex.SetBackgroundColor(colorBackground)

	s.input.SetLabel("filter ").
		SetLabelColor(colorAttrName).
		SetFieldBackgroundColor(colorBackground).
		SetFieldTextColor(colorText)

	s.input.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			if s.cancel != nil {
				s.cancel()
			}
			return nil
		case tcell.KeyUp:
			s.walkHistory(-1)
			return nil
		case tcell.KeyDown:
			s.walkHistory(1)
			return nil
		case tcell.KeyCtrlS:
			// Ctrl-S cycles the scope without leaving the field, so the filter
			// being typed survives.
			s.scope = s.scope.Next()
			s.render()
			return nil
		}
		return ev
	})

	s.input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		filter := strings.TrimSpace(s.input.GetText())
		if filter == "" {
			if s.cancel != nil {
				s.cancel()
			}
			return
		}
		s.remember(filter)
		if s.run != nil {
			s.run(ldapx.Query{BaseDN: s.base, Scope: s.scope, Filter: filter})
		}
	})

	s.AddItem(s.info, 1, 0, false).AddItem(s.input, 1, 0, true)
	return s
}

// open readies the bar for a new search under base.
func (s *searchBar) open(base string) {
	s.base = base
	s.pos = len(s.history)
	s.draft = ""
	s.input.SetText("")
	s.render()
}

func (s *searchBar) render() {
	base := s.base
	if strings.TrimSpace(base) == "" {
		base = "(nothing selected)"
	}
	s.info.SetText(fmt.Sprintf(
		"[%s]scope[-] %s  [%s]under[-] %s   [%s]ctrl-s scope · ↑↓ history · enter search · esc cancel[-]",
		tag(colorAttrName), s.scope,
		tag(colorAttrName), tview.Escape(base),
		tag(colorDim)))
}

// remember adds a filter to the session's history, moving a repeat to the end
// rather than storing it twice.
func (s *searchBar) remember(filter string) {
	for i, h := range s.history {
		if h == filter {
			s.history = append(s.history[:i], s.history[i+1:]...)
			break
		}
	}
	s.history = append(s.history, filter)
	s.pos = len(s.history)
}

// walkHistory steps through past filters. Stepping past the newest returns to
// whatever was being typed.
func (s *searchBar) walkHistory(delta int) {
	if len(s.history) == 0 {
		return
	}
	if s.pos == len(s.history) {
		s.draft = s.input.GetText()
	}

	pos := s.pos + delta
	if pos < 0 {
		pos = 0
	}
	if pos > len(s.history) {
		pos = len(s.history)
	}
	s.pos = pos

	if pos == len(s.history) {
		s.input.SetText(s.draft)
		return
	}
	s.input.SetText(s.history[pos])
}

// resultsPane is the flat list of search hits that replaces the tree while a
// search is showing.
type resultsPane struct {
	*tview.List

	entries []ldapx.Entry
	query   ldapx.Query
	cookie  []byte
	// loading guards the load-more row: it is easy to press enter on it twice
	// before the first page lands, and without this that fetches the same
	// cookie twice and lists the same entries twice.
	loading bool

	// selected fires as the cursor moves, so the object pane keeps up.
	selected func(dn string)
	// chosen fires on enter: the user wants this entry in the tree.
	chosen func(dn string)
	// more fires on the trailing "load more" row.
	more func()
	// closed fires on escape.
	closed func()
}

func newResultsPane() *resultsPane {
	r := &resultsPane{List: tview.NewList()}
	r.ShowSecondaryText(false)
	r.SetBackgroundColor(colorBackground)
	r.SetMainTextColor(colorText).
		SetSelectedBackgroundColor(colorSelected).
		SetSelectedTextColor(tcell.ColorWhite)
	r.SetBorder(true).
		SetTitle(" Results ").
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)

	r.SetChangedFunc(func(i int, _, _ string, _ rune) {
		if r.selected == nil {
			return
		}
		if i >= 0 && i < len(r.entries) {
			r.selected(r.entries[i].DN)
		}
	})
	r.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			if r.closed != nil {
				r.closed()
			}
			return nil
		}
		switch ev.Rune() {
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		case 'q':
			if r.closed != nil {
				r.closed()
			}
			return nil
		}
		return ev
	})
	return r
}

// show renders a page of hits. appendPage keeps what is already listed.
func (r *resultsPane) show(q ldapx.Query, page *ldapx.Page, appendPage bool) {
	if !appendPage {
		r.Clear()
		r.entries = nil
	} else {
		r.dropMoreRow()
	}
	r.query = q
	r.cookie = page.Cookie
	r.loading = false
	r.entries = append(r.entries, page.Entries...)

	for i := range page.Entries {
		e := page.Entries[i]
		dn := e.DN
		r.AddItem(tview.Escape(resultLabel(&e)), "", 0, func() {
			if r.chosen != nil {
				r.chosen(dn)
			}
		})
	}

	switch {
	case page.More():
		r.AddItem(fmt.Sprintf("%s %d so far, enter for more", iconMore, len(r.entries)), "", 0, func() {
			if r.more != nil {
				r.more()
			}
		})
	case page.Truncated:
		r.AddItem(fmt.Sprintf("%s first %d only (no paging)", iconMore, len(r.entries)), "", 0, nil)
	}

	r.SetTitle(fmt.Sprintf(" %d for %s ", len(r.entries), tview.Escape(q.Filter)))
	if len(r.entries) == 0 {
		r.AddItem("nothing matched", "", 0, nil)
	}
}

// dropMoreRow removes the trailing load-more row before another page lands.
func (r *resultsPane) dropMoreRow() {
	if n := r.GetItemCount(); n > len(r.entries) {
		r.RemoveItem(n - 1)
	}
}

// hasMore reports whether another page can be fetched right now.
func (r *resultsPane) hasMore() bool { return len(r.cookie) > 0 && !r.loading }

func resultLabel(e *ldapx.Entry) string {
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
	return fmt.Sprintf("%s %s", icon, e.DN)
}
