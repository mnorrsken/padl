package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ldapx"
)

// profileListActions are the callbacks the profile list needs from the app.
type profileListActions struct {
	connect func(config.Profile)
	edit    func(config.Profile)
	add     func()
	remove  func(config.Profile)
	close   func()
}

// profileList is the server picker. It is the first thing a new user sees, so
// an empty list says what to do rather than showing nothing.
func profileList(profiles []config.Profile, act profileListActions) tview.Primitive {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetBackgroundColor(colorBackground)
	list.SetMainTextColor(colorText).
		SetSecondaryTextColor(colorDim).
		SetSelectedBackgroundColor(colorSelected).
		SetSelectedTextColor(tcell.ColorWhite)

	for i := range profiles {
		p := profiles[i]
		// Escaped: tview reads square brackets in list text as style tags, and a
		// bind DN is free to contain them.
		list.AddItem(tview.Escape(p.Display()), tview.Escape(profileSummary(p)), 0,
			func() { act.connect(p) })
	}

	if len(profiles) == 0 {
		list.AddItem("No servers yet", "press a to add one", 0, func() { act.add() })
	}

	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			act.close()
			return nil
		}
		idx := list.GetCurrentItem()
		inRange := idx >= 0 && idx < len(profiles)
		switch ev.Rune() {
		case 'a':
			act.add()
			return nil
		case 'e':
			if inRange {
				act.edit(profiles[idx])
			}
			return nil
		case 'd':
			if inRange {
				act.remove(profiles[idx])
			}
			return nil
		case 'q':
			act.close()
			return nil
		}
		return ev
	})

	list.SetBorder(true).
		SetTitle(" Servers — enter connect · a add · e edit · d delete · esc close ").
		SetTitleColor(colorTitle).
		SetBorderColor(colorBorder).
		SetBackgroundColor(colorBackground)

	return center(list, 78, 22)
}

// profileSummary is the one-line description under each entry in the list.
func profileSummary(p config.Profile) string {
	bind := "anonymous"
	if p.Bind == config.BindSimple {
		bind = p.BindDN
	}
	return fmt.Sprintf("%s · %s · %s", p.URL(), p.Security, bind)
}

var (
	securityOptions = []string{
		string(config.SecurityLDAPS),
		string(config.SecurityStartTLS),
		string(config.SecurityNone),
	}
	bindOptions = []string{
		string(config.BindSimple),
		string(config.BindAnonymous),
	}
	passwordOptions = []string{
		string(config.PasswordKeyring),
		string(config.PasswordPrompt),
		string(config.PasswordEnv),
	}
)

func indexOf(options []string, want string) int {
	for i, o := range options {
		if o == want {
			return i
		}
	}
	return 0
}

// profileForm is the add/edit dialog.
//
// isNew controls whether the ID can still be changed: the ID keys both the
// keychain entry and the pinned certificate, so letting it change under an
// existing profile would silently orphan both.
func profileForm(p config.Profile, isNew bool, onSave func(config.Profile), onCancel func()) tview.Primitive {
	edited := p
	if edited.Port == 0 {
		edited.Port = config.DefaultPort(edited.Security)
	}

	form := tview.NewForm()
	form.SetBackgroundColor(colorBackground)
	form.SetFieldBackgroundColor(tcell.ColorDarkSlateGray)
	form.SetLabelColor(colorAttrName)

	hint := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	hint.SetBackgroundColor(colorBackground)
	setHint := func(color tcell.Color, format string, args ...any) {
		hint.SetText(fmt.Sprintf("[%s]%s[-]", tag(color), tview.Escape(fmt.Sprintf(format, args...))))
	}
	setHint(colorDim, "The bind DN is a full DN, e.g. uid=admin,ou=people,dc=example,dc=com.")

	if isNew {
		form.AddInputField("ID", edited.ID, 30, nil, func(t string) { edited.ID = strings.TrimSpace(t) })
	} else {
		form.AddTextView("ID", edited.ID, 30, 1, false, false)
	}
	form.AddInputField("Name", edited.Name, 40, nil, func(t string) { edited.Name = t })
	form.AddInputField("Host", edited.Host, 40, nil, func(t string) { edited.Host = strings.TrimSpace(t) })

	portField := func() *tview.InputField {
		item, _ := form.GetFormItemByLabel("Port").(*tview.InputField)
		return item
	}

	form.AddInputField("Port", strconv.Itoa(edited.Port), 8,
		func(text string, _ rune) bool {
			if text == "" {
				return true
			}
			n, err := strconv.Atoi(text)
			return err == nil && n > 0 && n <= 65535
		},
		func(t string) {
			n, err := strconv.Atoi(strings.TrimSpace(t))
			if err != nil {
				edited.Port = 0
				return
			}
			edited.Port = n
		})

	form.AddDropDown("Security", securityOptions, indexOf(securityOptions, string(edited.Security)),
		func(option string, _ int) {
			was := edited.Security
			edited.Security = config.Security(option)
			// Follow the conventional port as long as the user is still on the
			// default for the previous transport; once they type their own, it
			// stays put.
			if f := portField(); f != nil && edited.Port == config.DefaultPort(was) {
				edited.Port = config.DefaultPort(edited.Security)
				f.SetText(strconv.Itoa(edited.Port))
			}
			if edited.Security == config.SecurityNone {
				setHint(colorWarn, "Plain LDAP sends the bind password in clear text.")
			} else {
				setHint(colorDim, "The certificate is checked against the system trust store first; anything else asks you once.")
			}
		})

	form.AddDropDown("Bind", bindOptions, indexOf(bindOptions, string(edited.Bind)),
		func(option string, _ int) {
			edited.Bind = config.BindMethod(option)
			if edited.Bind == config.BindAnonymous {
				setHint(colorDim, "Anonymous bind is refused by most Active Directory servers.")
			}
		})
	form.AddInputField("Bind DN", edited.BindDN, 60, nil, func(t string) { edited.BindDN = strings.TrimSpace(t) })
	form.AddDropDown("Password from", passwordOptions, indexOf(passwordOptions, string(edited.PasswordRef)),
		func(option string, _ int) {
			edited.PasswordRef = config.PasswordRef(option)
			if edited.PasswordRef == config.PasswordEnv {
				setHint(colorDim, "Reads %s at connect time.", config.EnvVar(idOrPlaceholder(edited.ID)))
			}
		})

	form.AddInputField("Base DN", edited.BaseDN, 60, nil, func(t string) { edited.BaseDN = strings.TrimSpace(t) })
	form.AddInputField("Timeout (s)", strconv.Itoa(edited.Timeout()), 8, digitsOnly,
		func(t string) { edited.TimeoutSeconds = atoiOr(t, config.DefaultTimeoutSeconds) })
	form.AddInputField("Max children", strconv.Itoa(edited.Limit()), 8, digitsOnly,
		func(t string) { edited.PageSize = atoiOr(t, config.DefaultPageSize) })

	form.AddButton("Save", func() {
		candidate := edited
		if candidate.Port == 0 {
			candidate.Port = config.DefaultPort(candidate.Security)
		}
		if err := candidate.Validate(); err != nil {
			setHint(colorError, "%v", err)
			return
		}
		// Catch a bare username here rather than letting the server answer it
		// with a result code that does not name the problem.
		if candidate.Bind == config.BindSimple {
			if err := ldapx.ValidateDN(candidate.BindDN); err != nil {
				setHint(colorError, "%v", err)
				return
			}
		}
		onSave(candidate)
	})
	form.AddButton("Cancel", onCancel)

	title := " Edit server "
	if isNew {
		title = " Add server "
	}

	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(hint, 2, 0, false)
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

	return center(frame, 84, 26)
}

func idOrPlaceholder(id string) string {
	if strings.TrimSpace(id) == "" {
		return "<id>"
	}
	return id
}

func digitsOnly(text string, _ rune) bool {
	if text == "" {
		return true
	}
	_, err := strconv.Atoi(text)
	return err == nil
}

func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
