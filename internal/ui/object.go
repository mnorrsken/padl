package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/ldapx"
)

// objectRow is one line of the attribute table. Multi-valued attributes take
// one row per value, with the name blank after the first — the same shape
// ldapsearch output has, which is what people already read.
type objectRow struct {
	attr        string
	value       ldapx.Value
	first       bool
	operational bool
	// link is the DN this value points at, when it points at one that is
	// actually in the tree. Empty for everything else.
	link string
}

// objectPane is the right-hand side: the DN, then the attributes.
type objectPane struct {
	*tview.Flex

	header *tview.TextView
	table  *tview.Table

	entry       *ldapx.Entry
	rows        []objectRow
	operational bool

	// bases are the naming contexts currently in the tree. A value only counts
	// as a link if it lands inside one of them.
	bases []string

	// inspect is called when a value is opened for a closer look.
	inspect func(attr string, v ldapx.Value)
	// follow is called when a DN-valued attribute is opened.
	follow func(dn string)
}

func newObjectPane() *objectPane {
	o := &objectPane{
		Flex:   tview.NewFlex().SetDirection(tview.FlexRow),
		header: tview.NewTextView().SetDynamicColors(true).SetWrap(true),
		table:  tview.NewTable(),
	}
	o.header.SetBackgroundColor(colorBackground)
	o.table.SetBackgroundColor(colorBackground)
	o.table.SetSelectable(true, false).
		SetFixed(1, 0).
		SetSeparator(' ')
	o.table.SetSelectedStyle(tcell.StyleDefault.Background(colorSelected).Foreground(tcell.ColorWhite))

	o.SetBorder(true).
		SetTitle(" Object ").
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)

	o.AddItem(o.header, 2, 0, false).AddItem(o.table, 0, 1, true)

	o.table.SetSelectedFunc(func(row, _ int) {
		r, ok := o.rowAt(row)
		if !ok {
			return
		}
		// A reference to another entry is worth more as a jump than as a
		// popup, so following wins over inspecting.
		if r.link != "" && o.follow != nil {
			o.follow(r.link)
			return
		}
		if o.inspect != nil {
			o.inspect(r.attr, r.value)
		}
	})
	return o
}

// setBases tells the pane which naming contexts are in the tree, which is what
// decides whether a DN-shaped value is followable.
func (o *objectPane) setBases(bases []string) { o.bases = bases }

// rowAt maps a table row back to the attribute value behind it, accounting for
// the header row.
func (o *objectPane) rowAt(row int) (objectRow, bool) {
	i := row - 1
	if i < 0 || i >= len(o.rows) {
		return objectRow{}, false
	}
	return o.rows[i], true
}

// showOperational reports whether operational attributes are currently shown.
func (o *objectPane) showOperational() bool { return o.operational }

// setOperational records the toggle. The caller re-fetches, since operational
// attributes cost an extra round trip and are not held in reserve.
func (o *objectPane) setOperational(on bool) { o.operational = on }

// clear puts the pane into its empty state with an explanatory line, so a blank
// right-hand pane never looks like a bug.
func (o *objectPane) clear(reason string) {
	o.entry = nil
	o.rows = nil
	o.table.Clear()
	o.header.SetText(fmt.Sprintf("[%s]%s[-]", tag(colorDim), escape(reason)))
}

// setBusy shows what is being loaded while the read is in flight.
func (o *objectPane) setBusy(dn string) {
	o.table.Clear()
	o.rows = nil
	o.header.SetText(fmt.Sprintf("[%s]%s[-]\n[%s]loading…[-]",
		tag(colorAccent), escape(dn), tag(colorDim)))
}

// show renders an entry.
func (o *objectPane) show(e *ldapx.Entry) {
	o.entry = e
	o.rows = buildRows(e, o.bases)

	o.header.SetText(fmt.Sprintf("[%s]dn:[-] %s", tag(colorAttrName), escape(e.DN)))

	o.table.Clear()
	o.table.SetCell(0, 0, headerCell("Attribute"))
	o.table.SetCell(0, 1, headerCell("Value"))

	for i, r := range o.rows {
		row := i + 1

		name := ""
		if r.first {
			name = r.attr
		}
		nameColor := colorAttrName
		if r.operational {
			nameColor = colorDim
		}
		o.table.SetCell(row, 0, tview.NewTableCell(escape(name)).
			SetTextColor(nameColor).
			SetSelectable(true).
			SetMaxWidth(28))

		valueColor := colorText
		attrs := tcell.AttrNone
		switch {
		case r.link != "":
			// Underlined and coloured, with no trailing label: repeating
			// "(enter to follow)" down a group with two hundred members is
			// noise, and the styling already says it. What enter does is on
			// the key hints line.
			valueColor = colorLink
			attrs = tcell.AttrUnderline
		case r.operational:
			valueColor = colorDim
		case r.value.Binary:
			valueColor = colorBinary
		}
		if r.operational && r.link != "" {
			valueColor = colorDim
		}
		o.table.SetCell(row, 1, tview.NewTableCell(escape(oneLine(r.value.Text))).
			SetTextColor(valueColor).
			SetAttributes(attrs).
			SetSelectable(true).
			SetExpansion(1))
	}

	if len(o.rows) > 0 {
		o.table.Select(1, 0)
	}
	o.table.ScrollToBeginning()
}

func headerCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).
		SetTextColor(colorTitle).
		SetAttributes(tcell.AttrBold).
		SetSelectable(false)
}

// oneLine keeps a multi-line value from breaking the table layout. The full
// text stays reachable through the value inspector.
func oneLine(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	r := strings.NewReplacer("\r\n", " ⏎ ", "\n", " ⏎ ", "\r", " ⏎ ")
	return r.Replace(s)
}

// buildRows flattens an entry into display rows.
//
// objectClass comes first because it is what tells you what you are looking at;
// the rest are alphabetical, with operational attributes last so the entry's
// own data is never pushed off the top of the pane.
func buildRows(e *ldapx.Entry, bases []string) []objectRow {
	attrs := append([]ldapx.Attribute(nil), e.Attributes...)
	sort.SliceStable(attrs, func(i, j int) bool {
		if attrs[i].Operational != attrs[j].Operational {
			return !attrs[i].Operational
		}
		ni, nj := strings.ToLower(attrs[i].Name), strings.ToLower(attrs[j].Name)
		if (ni == "objectclass") != (nj == "objectclass") {
			return ni == "objectclass"
		}
		return ni < nj
	})

	var rows []objectRow
	for _, a := range attrs {
		values := ldapx.FormatAll(a)
		if len(values) == 0 {
			// An attribute present with no values is worth showing as such
			// rather than silently dropping.
			rows = append(rows, objectRow{
				attr:        a.Name,
				value:       ldapx.Value{Text: "(no values)"},
				first:       true,
				operational: a.Operational,
			})
			continue
		}
		for i, v := range values {
			link := ""
			// A binary value is never a reference, whatever its bytes spell.
			if !v.Binary && ldapx.IsDNUnder(v.Text, bases) {
				link = strings.TrimSpace(v.Text)
			}
			rows = append(rows, objectRow{
				attr:        a.Name,
				value:       v,
				first:       i == 0,
				operational: a.Operational,
				link:        link,
			})
		}
	}
	return rows
}

// currentValue is the value under the cursor, for copy and inspect.
func (o *objectPane) currentValue() (objectRow, bool) {
	row, _ := o.table.GetSelection()
	return o.rowAt(row)
}
