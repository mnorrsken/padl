package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/ldapx"
)

// splitFingerprint breaks a colon-separated SHA-256 into two lines of sixteen
// bytes.
//
// The whole 95-character string does not fit an 80-column terminal, and a
// fingerprint that soft-wraps mid-byte is exactly the thing an operator cannot
// compare by eye — which would defeat the point of showing it.
func splitFingerprint(fp string) []string {
	parts := strings.Split(fp, ":")
	if len(parts) <= 16 {
		return []string{fp}
	}
	half := (len(parts) + 1) / 2
	return []string{
		strings.Join(parts[:half], ":") + ":",
		strings.Join(parts[half:], ":"),
	}
}

// centerLarge floats a primitive that wants as much room as the terminal will
// give it, keeping a margin on every side. Used for the help, which grows with
// the key list and would otherwise be cut off in a fixed-size box.
func centerLarge(p tview.Primitive, maxWidth int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 1, 0, false).
			AddItem(p, 0, 1, true).
			AddItem(nil, 1, 0, false), maxWidth, 0, true).
		AddItem(nil, 0, 1, false)
}

// center wraps a primitive in enough empty space to float it over the layout.
func center(p tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, height, 0, true).
			AddItem(nil, 0, 1, false), width, 0, true).
		AddItem(nil, 0, 1, false)
}

// certPrompt is the trust-on-first-use decision.
//
// It shows every field an operator needs to compare against what the server
// admin told them — fingerprint above all — and it never pre-selects "trust".
// The changed-certificate case gets different wording and a red border, because
// it means something that was working now presents different keys, and that is
// worth a second look rather than a reflex Enter.
func certPrompt(cte *ldapx.CertTrustError, onAccept, onReject func()) tview.Primitive {
	var b strings.Builder

	title := " Untrusted certificate "
	border := colorWarn
	if cte.Reason == ldapx.TrustChanged {
		title = " CERTIFICATE CHANGED "
		border = colorError
		fmt.Fprintf(&b, "[%s]The certificate for %s has changed since you trusted it.[-]\n",
			tag(colorError), tview.Escape(cte.Host))
		fmt.Fprintf(&b, "[%s]If nobody replaced it on purpose, stop and find out why.[-]\n\n",
			tag(colorError))
	} else {
		fmt.Fprintf(&b, "[%s]%s could not be verified against the system trust store.[-]\n\n",
			tag(colorWarn), tview.Escape(cte.Host))
	}

	row := func(label, value string) {
		fmt.Fprintf(&b, "[%s]%-12s[-] %s\n", tag(colorAttrName), label, tview.Escape(value))
	}
	row("Subject", cte.Subject)
	row("Issuer", cte.Issuer)
	if len(cte.SANs) > 0 {
		row("SANs", strings.Join(cte.SANs, ", "))
	}
	row("Valid from", cte.NotBefore.Local().Format("2006-01-02 15:04:05 MST"))
	row("Valid to", cte.NotAfter.Local().Format("2006-01-02 15:04:05 MST"))

	fingerprint := func(label string, color tcell.Color, fp string) {
		for i, line := range splitFingerprint(fp) {
			name := ""
			if i == 0 {
				name = label
			}
			fmt.Fprintf(&b, "[%s]%-12s[-] [%s]%s[-]\n", tag(colorAttrName), name, tag(color), line)
		}
	}
	fingerprint("SHA-256", colorAccent, cte.Fingerprint)
	if cte.Existing != nil {
		fingerprint("was", colorDim, cte.Existing.Fingerprint)
	}
	if cte.Expired() {
		fmt.Fprintf(&b, "\n[%s]This certificate is outside its validity window.[-]\n", tag(colorError))
	}
	if cte.VerifyErr != nil {
		fmt.Fprintf(&b, "\n[%s]%s[-]\n", tag(colorDim), tview.Escape(cte.VerifyErr.Error()))
	}
	fmt.Fprintf(&b, "\nCompare the SHA-256 with what the directory admin published before trusting it.")

	text := tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetText(b.String())
	text.SetBackgroundColor(colorBackground)

	acceptLabel := "Trust and pin"
	if cte.Reason == ldapx.TrustChanged {
		acceptLabel = "Replace pin"
	}

	form := tview.NewForm().
		SetButtonsAlign(tview.AlignCenter).
		AddButton("Cancel", onReject).
		AddButton(acceptLabel, onAccept)
	form.SetBackgroundColor(colorBackground)
	// Cancel is index 0 and gets focus, so a reflexive Enter declines rather
	// than trusts.
	form.SetFocus(0)

	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(text, 0, 1, false).
		AddItem(form, 3, 0, true)
	frame.SetBorder(true).
		SetTitle(title).
		SetTitleColor(border).
		SetBorderColor(border).
		SetBackgroundColor(colorBackground)

	return center(frame, 84, 24)
}

// passwordPrompt asks for a bind password.
//
// note carries whatever the caller wants to explain — most usefully that the
// OS keychain could not be reached — so a headless box gives a reason instead
// of an unexplained password box.
func passwordPrompt(profileName, bindDN, note string, canSave bool, onSubmit func(password string, save bool), onCancel func()) tview.Primitive {
	password := ""
	save := canSave

	form := tview.NewForm()
	form.AddPasswordField("Password", "", 40, '*', func(t string) { password = t })
	if canSave {
		form.AddCheckbox("Save to OS keychain", save, func(c bool) { save = c })
	}
	form.AddButton("Connect", func() { onSubmit(password, save) }).
		AddButton("Cancel", onCancel)
	form.SetBackgroundColor(colorBackground)
	form.SetFieldBackgroundColor(tcell.ColorDarkSlateGray)

	info := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	info.SetBackgroundColor(colorBackground)
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]bind dn:[-] %s\n", tag(colorAttrName), tview.Escape(bindDN))
	if note != "" {
		fmt.Fprintf(&b, "[%s]%s[-]\n", tag(colorWarn), tview.Escape(note))
	}
	info.SetText(b.String())

	height := 3
	if note != "" {
		height = 4
	}

	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(info, height, 0, false).
		AddItem(form, 0, 1, true)
	frame.SetBorder(true).
		SetTitle(fmt.Sprintf(" Bind to %s ", profileName)).
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)

	return center(frame, 70, 13)
}

// valueInspector shows a value in full: a hex dump for binary, the raw text
// otherwise. This is the escape hatch for everything the one-line table cell
// cannot show.
func valueInspector(attr string, v ldapx.Value, onClose func()) tview.Primitive {
	body := tview.NewTextView().SetWrap(true).SetScrollable(true)
	body.SetBackgroundColor(colorBackground)
	if v.Binary {
		body.SetWrap(false).SetText(ldapx.HexDump(v.Raw))
	} else {
		body.SetText(v.Text)
	}

	frame := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(body, 0, 1, true)
	frame.SetBorder(true).
		SetTitle(fmt.Sprintf(" %s — %d bytes (esc to close) ", attr, len(v.Raw))).
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)
	frame.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape || ev.Rune() == 'q' {
			onClose()
			return nil
		}
		return ev
	})
	return center(frame, 80, 24)
}

const helpText = `[::b]Panes[-::-]
  Tab / Shift-Tab   move between the left pane and the object pane
  /                 search below the selected entry
  g                 go to a DN you type in
  B                 bookmarks       b   bookmark / unbookmark the selection
  p                 profiles        c   connect / disconnect
  ?                 this help       q   quit
  Esc               cancel whatever is loading, or close what is open

[::b]Tree[-::-]
  Up / Down, j / k  move
  Right, l, Enter   expand — loads children on first open
  Left, h           collapse, or step up to the parent
  Enter on "…"      load the next page of a large container
  r                 reload the selected node from the server
  y                 copy the selected DN
  a                 show / hide the hidden naming contexts
  L                 copy the entry as LDIF
  E                 export the entry and everything under it to a file

[::b]Search[-::-]
  /                 open the filter bar, based at the selected entry
  Ctrl-S            cycle the scope: sub, base, one
  Up / Down         walk this session's filter history
  Enter             run it — results replace the tree on the left

[::b]Results[-::-]
  Up / Down, j / k  move; the object pane follows
  Enter             go to that entry in the tree
  y                 copy the selected DN
  Esc               back to the tree

[::b]Object pane[-::-]
  Up / Down, j / k  move between values
  Enter             follow a DN to that entry, or inspect the value in full
  o                 show / hide operational attributes
  y                 copy the selected value
  L                 copy the entry as LDIF

[::b]Files[-::-]
  Profiles and pinned certificates live in the PADL config directory;
  padl -paths prints where. Bind passwords are never written there:
  they go to the OS keychain, come from PADL_PASSWORD_<ID>, or are
  typed on each connect.`

func helpView(onClose func()) tview.Primitive {
	body := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetText(helpText)
	body.SetBackgroundColor(colorBackground)
	body.SetBorder(true).
		SetTitle(" Keys (esc to close) ").
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)
	body.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape || ev.Rune() == 'q' || ev.Rune() == '?' {
			onClose()
			return nil
		}
		return ev
	})
	return centerLarge(body, 76)
}

// bookmarkList is the saved-DN picker.
func bookmarkList(profileName string, dns []string, onChoose func(string), onDelete func(string), onClose func()) tview.Primitive {
	list := tview.NewList().ShowSecondaryText(false)
	list.SetBackgroundColor(colorBackground)
	list.SetMainTextColor(colorText).
		SetSelectedBackgroundColor(colorSelected).
		SetSelectedTextColor(tcell.ColorWhite)

	for _, dn := range dns {
		target := dn
		list.AddItem(tview.Escape(dn), "", 0, func() { onChoose(target) })
	}
	if len(dns) == 0 {
		list.AddItem("No bookmarks yet", "", 0, nil)
	}

	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape || ev.Rune() == 'q' {
			onClose()
			return nil
		}
		if ev.Rune() == 'd' {
			i := list.GetCurrentItem()
			if i >= 0 && i < len(dns) {
				onDelete(dns[i])
			}
			return nil
		}
		return ev
	})

	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" Bookmarks — %s · enter go · d delete · esc close ", tview.Escape(profileName))).
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)

	return center(list, 84, 20)
}

// promptBox asks for a single line of text.
func promptBox(title, label, value, hint string, onSubmit func(string), onCancel func()) tview.Primitive {
	text := value

	form := tview.NewForm()
	form.SetBackgroundColor(colorBackground)
	form.SetFieldBackgroundColor(tcell.ColorDarkSlateGray)
	form.SetLabelColor(colorAttrName)
	form.AddInputField(label, value, 70, nil, func(t string) { text = t })
	form.AddButton("OK", func() { onSubmit(text) })
	form.AddButton("Cancel", onCancel)

	info := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	info.SetBackgroundColor(colorBackground)
	if hint != "" {
		info.SetText(fmt.Sprintf("[%s]%s[-]", tag(colorDim), tview.Escape(hint)))
	}

	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(info, 2, 0, false)
	frame.SetBorder(true).
		SetTitle(title).
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)
	frame.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			onCancel()
			return nil
		}
		return ev
	})

	return center(frame, 84, 11)
}

// messageBox is the generic one-button dialog for errors worth stopping on.
func messageBox(title, message string, color tcell.Color, onClose func()) tview.Primitive {
	m := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(int, string) { onClose() })
	m.SetBackgroundColor(colorBackground)
	m.SetBorderColor(color).SetTitle(title).SetTitleColor(color)
	return m
}

// confirmBox asks a yes/no question, defaulting to no.
func confirmBox(title, message string, onYes, onNo func()) tview.Primitive {
	m := tview.NewModal().
		SetText(message).
		AddButtons([]string{"Cancel", "Yes"}).
		SetDoneFunc(func(idx int, _ string) {
			if idx == 1 {
				onYes()
				return
			}
			onNo()
		})
	m.SetBackgroundColor(colorBackground)
	m.SetBorderColor(colorWarn).SetTitle(title).SetTitleColor(colorWarn)
	return m
}
