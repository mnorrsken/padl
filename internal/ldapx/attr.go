package ldapx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Value is one attribute value ready to put on screen.
type Value struct {
	// Text is what the object pane shows.
	Text string
	// Binary is true when Text is a rendering rather than the value itself, so
	// the UI knows to offer a hex dump instead of letting it be edited as text.
	Binary bool
	// Raw is the value as it came off the wire.
	Raw []byte
}

// String satisfies fmt.Stringer for convenience in tests and status lines.
func (v Value) String() string { return v.Text }

// binaryAttrs are attributes whose values are never text, regardless of what
// the bytes happen to look like.
var binaryAttrs = map[string]bool{
	"objectguid":                true, // Active Directory
	"objectsid":                 true, // Active Directory
	"guid":                      true, // eDirectory
	"usercertificate":           true,
	"cacertificate":             true,
	"usersmimecertificate":      true,
	"jpegphoto":                 true,
	"thumbnailphoto":            true,
	"thumbnaillogo":             true,
	"photo":                     true,
	"audio":                     true,
	"userpkcs12":                true,
	"certificaterevocationlist": true,
	"authorityrevocationlist":   true,
	"crosscertificatepair":      true,
	"unicodepwd":                true,
	"nspmpassword":              true, // eDirectory
	"publickey":                 true,
}

// generalizedTimeAttrs hold LDAP generalizedTime, which is readable but ugly.
var generalizedTimeAttrs = map[string]bool{
	"whencreated":       true,
	"whenchanged":       true,
	"createtimestamp":   true,
	"modifytimestamp":   true,
	"pwdchangedtime":    true,
	"pwdlastset":        true, // AD: FILETIME, handled separately
	"expirationtime":    true,
	"logintime":         true, // eDirectory
	"passwordexpiratio": true,
}

// filetimeAttrs hold Windows FILETIME as a decimal string: 100ns ticks since
// 1601. AD reports several important timestamps this way.
var filetimeAttrs = map[string]bool{
	"pwdlastset":         true,
	"lastlogon":          true,
	"lastlogontimestamp": true,
	"accountexpires":     true,
	"badpasswordtime":    true,
	"lastlogoff":         true,
}

// Format renders one raw attribute value for display.
func Format(attr string, raw []byte) Value {
	name := strings.ToLower(attr)
	// Some servers tag attributes as ";binary"; the base name is what matters.
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}

	switch {
	case name == "objectguid" || name == "guid":
		if s, ok := formatGUID(raw); ok {
			return Value{Text: s, Binary: true, Raw: raw}
		}
	case name == "objectsid":
		if s, ok := formatSID(raw); ok {
			return Value{Text: s, Binary: true, Raw: raw}
		}
	case name == "useraccountcontrol":
		if s, ok := formatUAC(string(raw)); ok {
			return Value{Text: s, Raw: raw}
		}
	case filetimeAttrs[name]:
		if s, ok := formatFiletime(string(raw)); ok {
			return Value{Text: s, Raw: raw}
		}
	case generalizedTimeAttrs[name]:
		if s, ok := formatGeneralizedTime(string(raw)); ok {
			return Value{Text: s, Raw: raw}
		}
	}

	if binaryAttrs[name] || !utf8.Valid(raw) || hasControlBytes(raw) {
		return Value{Text: describeBinary(raw), Binary: true, Raw: raw}
	}
	return Value{Text: string(raw), Raw: raw}
}

// FormatAll renders every value of an attribute.
func FormatAll(a Attribute) []Value {
	out := make([]Value, len(a.Values))
	for i, v := range a.Values {
		out[i] = Format(a.Name, v)
	}
	return out
}

// hasControlBytes catches values that are valid UTF-8 but still not something
// to paste into a terminal. Tab, newline and carriage return are allowed
// through because plenty of legitimate text attributes contain them.
func hasControlBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}

func describeBinary(raw []byte) string {
	unit := "bytes"
	if len(raw) == 1 {
		unit = "byte"
	}
	return fmt.Sprintf("<binary, %d %s>", len(raw), unit)
}

// formatGUID renders a 16-byte Microsoft/eDirectory GUID. The first three
// fields are little-endian on the wire and big-endian in the printed form,
// which is why this cannot just be a hex dump with dashes.
func formatGUID(raw []byte) (string, bool) {
	if len(raw) != 16 {
		return "", false
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		binary.BigEndian.Uint16(raw[8:10]),
		raw[10:16],
	), true
}

// formatSID renders a Windows security identifier as S-R-A-S1-S2-…
// Layout: revision, sub-authority count, 6-byte big-endian authority, then that
// many little-endian 32-bit sub-authorities.
func formatSID(raw []byte) (string, bool) {
	if len(raw) < 8 {
		return "", false
	}
	revision := raw[0]
	subCount := int(raw[1])
	if len(raw) < 8+subCount*4 {
		return "", false
	}
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "S-%d-%d", revision, authority)
	for i := 0; i < subCount; i++ {
		off := 8 + i*4
		fmt.Fprintf(&b, "-%d", binary.LittleEndian.Uint32(raw[off:off+4]))
	}
	return b.String(), true
}

// generalizedTimeLayouts covers the spellings servers actually emit: with and
// without fractional seconds, with Z or a numeric offset, and the local-time
// form with no zone at all.
var generalizedTimeLayouts = []string{
	"20060102150405.0Z",
	"20060102150405.999999Z",
	"20060102150405Z",
	"20060102150405.0-0700",
	"20060102150405.999999-0700",
	"20060102150405-0700",
	"20060102150405",
}

func formatGeneralizedTime(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	for _, layout := range generalizedTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Local().Format("2006-01-02 15:04:05 MST"), true
		}
	}
	return "", false
}

// filetimeEpochOffset is the number of 100ns ticks between 1601-01-01 and the
// Unix epoch.
const filetimeEpochOffset = 116444736000000000

func formatFiletime(s string) (string, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return "", false
	}
	switch {
	case n == 0:
		return "0 (never / not set)", true
	case n >= 9223372036854775807:
		return "never expires", true
	case n < filetimeEpochOffset:
		return "", false
	}
	ticks := n - filetimeEpochOffset
	t := time.Unix(ticks/1e7, (ticks%1e7)*100).Local()
	return t.Format("2006-01-02 15:04:05 MST"), true
}

// uacFlags are the userAccountControl bits worth naming. Showing the decoded
// list matters because "512" vs "514" is the difference between an enabled and
// a disabled account, and nobody reads that from the number.
var uacFlags = []struct {
	bit  uint32
	name string
}{
	{0x0000001, "SCRIPT"},
	{0x0000002, "ACCOUNTDISABLE"},
	{0x0000008, "HOMEDIR_REQUIRED"},
	{0x0000010, "LOCKOUT"},
	{0x0000020, "PASSWD_NOTREQD"},
	{0x0000040, "PASSWD_CANT_CHANGE"},
	{0x0000080, "ENCRYPTED_TEXT_PWD_ALLOWED"},
	{0x0000100, "TEMP_DUPLICATE_ACCOUNT"},
	{0x0000200, "NORMAL_ACCOUNT"},
	{0x0000800, "INTERDOMAIN_TRUST_ACCOUNT"},
	{0x0001000, "WORKSTATION_TRUST_ACCOUNT"},
	{0x0002000, "SERVER_TRUST_ACCOUNT"},
	{0x0010000, "DONT_EXPIRE_PASSWORD"},
	{0x0020000, "MNS_LOGON_ACCOUNT"},
	{0x0040000, "SMARTCARD_REQUIRED"},
	{0x0080000, "TRUSTED_FOR_DELEGATION"},
	{0x0100000, "NOT_DELEGATED"},
	{0x0200000, "USE_DES_KEY_ONLY"},
	{0x0400000, "DONT_REQ_PREAUTH"},
	{0x0800000, "PASSWORD_EXPIRED"},
	{0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
	{0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

func formatUAC(s string) (string, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return "", false
	}
	v := uint32(n)
	var set []string
	for _, f := range uacFlags {
		if v&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	if len(set) == 0 {
		return s, true
	}
	return fmt.Sprintf("%s (%s)", s, strings.Join(set, " | ")), true
}

// HexDump renders a binary value for the detail popup, in the usual
// offset / hex / ASCII layout.
func HexDump(raw []byte) string {
	return strings.TrimRight(hex.Dump(raw), "\n")
}
