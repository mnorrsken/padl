package ldapx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
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

// rendering says how one attribute's values are turned into something readable.
type rendering struct {
	// render produces the display text. Reporting false leaves the value to the
	// generic handling below, so a renderer never has to be certain: a value
	// that is not the shape it expects falls through to plain text or a hex
	// dump rather than becoming a lie.
	render func(raw []byte) (string, bool)
	// binary marks a value whose text is a rendering of bytes rather than the
	// bytes themselves. The object pane offers a hex dump for those.
	binary bool
}

// renderings is every attribute PADL knows how to say something about, keyed by
// lowercased name with any ";option" suffix stripped.
//
// Two kinds of rendering live here and the difference is deliberate. A value
// nobody can read — a GUID, a SID, a FILETIME — is *replaced* by its rendering.
// A value that is readable but means more than it says — a flag word, an
// enumerated type, an address with a prefix — keeps its original text and gains
// the meaning in parentheses, so what the user copies with `y` is still the
// value the directory holds.
var renderings = mergeRenderings(
	commonRenderings,
	adRenderings,
	exchangeRenderings,
	edirectoryRenderings,
	idmRenderings,
)

// commonRenderings are the standard LDAP operational attributes every server
// publishes, so they do not belong to any vendor's table.
var commonRenderings = map[string]rendering{
	"createtimestamp": decodeText(formatGeneralizedTime),
	"modifytimestamp": decodeText(formatGeneralizedTime),
}

// mergeRenderings folds the per-vendor tables into one. Names are expected not
// to collide; TestRenderingTablesDoNotCollide holds that to it, because a
// silent overwrite here would be a vendor's attribute quietly rendered by
// another's rules.
func mergeRenderings(tables ...map[string]rendering) map[string]rendering {
	out := map[string]rendering{}
	for _, t := range tables {
		for name, r := range t {
			out[name] = r
		}
	}
	return out
}

// baseAttrName lowercases an attribute description and drops its options, so
// "userCertificate;binary" and "userCertificate" look the same to the tables.
func baseAttrName(attr string) string {
	name := strings.ToLower(attr)
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}
	return name
}

// Format renders one raw attribute value for display.
func Format(attr string, raw []byte) Value {
	name := baseAttrName(attr)

	if r, ok := renderings[name]; ok {
		if text, ok := r.render(raw); ok {
			return Value{Text: text, Binary: r.binary, Raw: raw}
		}
	}

	if binaryAttrs[name] || !utf8.Valid(raw) || hasControlBytes(raw) {
		return Value{Text: describeBinary(raw), Binary: true, Raw: raw}
	}
	return Value{Text: string(raw), Raw: raw}
}

// ---------------------------------------------------------------- decoders
//
// The building blocks the vendor tables are written in. Each takes the shape a
// value arrives in and returns display text, or false to fall through.

// decodeText adapts a renderer that works on the value as a string, which is
// most of them: these attributes are integers written out in decimal.
func decodeText(f func(string) (string, bool)) rendering {
	return rendering{render: func(raw []byte) (string, bool) {
		if !utf8.Valid(raw) {
			return "", false
		}
		return f(string(raw))
	}}
}

// decodeBytes adapts a renderer that works on the raw octets, and marks the
// result as a rendering of binary rather than as the value itself.
func decodeBytes(f func([]byte) (string, bool)) rendering {
	return rendering{render: f, binary: true}
}

// flag is one named bit in a flag word.
type flag struct {
	bit  uint32
	name string
}

// bitField names the bits set in a flag word.
//
// The number is read as signed and then taken as unsigned 32 bits, because
// Active Directory writes these out signed: a global security group's groupType
// arrives as -2147483646, and the domain head's systemFlags as -1946157056.
// Reading either as unsigned would fail outright.
func bitField(flags []flag) func(string) (string, bool) {
	return func(s string) (string, bool) {
		s = strings.TrimSpace(s)
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > math.MaxUint32 || n < math.MinInt32 {
			return "", false
		}
		set := namedBits(uint32(n), flags)
		if len(set) == 0 {
			return s, true
		}
		return fmt.Sprintf("%s (%s)", s, strings.Join(set, " | ")), true
	}
}

// namedBits lists the flags set in v, taking more than one table because some
// values carry bits from two vocabularies at once — an eDirectory ACL holds
// rights bits alongside flags that mean the same thing whatever the rights are.
//
// Anything left over is appended as hex. A bit nobody has named is still a bit
// that is set, and silently dropping it would read as "not set".
func namedBits(v uint32, tables ...[]flag) []string {
	var set []string
	var known uint32
	for _, t := range tables {
		for _, f := range t {
			known |= f.bit
			if v&f.bit != 0 {
				set = append(set, f.name)
			}
		}
	}
	if rest := v &^ known; rest != 0 {
		set = append(set, fmt.Sprintf("0x%x", rest))
	}
	return set
}

// enumeration names a value that is one of a fixed set rather than a set of
// bits. The number stays: it is what a script or a Microsoft article will use.
func enumeration(names map[int64]string) func(string) (string, bool) {
	return func(s string) (string, bool) {
		s = strings.TrimSpace(s)
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return "", false
		}
		name, ok := names[n]
		if !ok {
			return "", false
		}
		return fmt.Sprintf("%s (%s)", s, name), true
	}
}

// Rendered reports whether PADL turns this attribute's values into something
// other than the value itself.
//
// The object pane has to know, because a rendered Text is a description and a
// description is never a reference to follow. An eDirectory ACL comes out as
// "[Entry Rights]: supervisor · subtree · cn=edir1,o=padl", which ends in a DN
// that really is in the tree and parses as one — so without this it would be
// underlined and enter would walk off to the trustee, which is not what the
// value points at.
func Rendered(attr string) bool {
	_, ok := renderings[baseAttrName(attr)]
	return ok
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
//
// Only ever called on valid UTF-8, so ranging over runes is safe — and it has
// to be runes rather than bytes to catch the C1 block below.
func hasControlBytes(b []byte) bool {
	for _, r := range string(b) {
		if isControlRune(r) {
			return true
		}
	}
	return false
}

// isControlRune reports whether r is something a terminal acts on rather than
// draws.
//
// C0 and DEL are the obvious half. The C1 block, U+0080 to U+009F, is the half
// that is easy to miss: it is perfectly valid UTF-8, so a byte-wise check waves
// it through, but U+009B is the eight-bit form of CSI and terminals in UTF-8
// mode do act on it.
func isControlRune(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	}
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// SafeText makes a server-supplied string safe to draw, replacing every control
// rune with U+FFFD.
//
// Attribute values go through Format, which turns anything with a control rune
// in it into a hex dump. DNs and attribute names have no such stage: they are
// drawn as they came off the wire, and nothing in LDAP stops a directory from
// putting an escape sequence in one.
//
// This is a second line rather than the only one. tview drops zero-width
// grapheme clusters — which is every control rune — before they ever reach
// tcell, so today an escape sequence in a DN is discarded on the way to the
// screen. That is an implementation detail of tview's draw loop, not something
// it promises, and PADL should not be relying on a dependency's rendering
// internals to decide what a hostile directory can put on the terminal. Making
// it explicit also makes the mangling visible instead of silent.
func SafeText(s string) string {
	if !strings.ContainsFunc(s, isControlRune) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControlRune(r) {
			return '�'
		}
		return r
	}, s)
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

// formatFiletimeInterval renders the durations Active Directory stores as
// *negative* FILETIME intervals: maxPwdAge, lockoutDuration and the rest of the
// domain password policy. A domain with a 30-minute lockout reports
// -18000000000, which says nothing to anybody.
//
// int64's minimum is the policy's "never": that is what maxPwdAge holds when
// passwords do not expire, and forceLogoff when nobody is forced off.
func formatFiletimeInterval(s string) (string, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return "", false
	}
	switch {
	case n == math.MinInt64:
		return "never", true
	case n == 0:
		return "0 (not set)", true
	case n > 0:
		// These are stored negative. A positive one is not an interval, so say
		// nothing rather than report a duration backwards.
		return "", false
	}
	return humanDuration(time.Duration(-n) * 100), true
}

// formatSecondsInterval renders the plain second counts eDirectory uses for the
// same kind of policy value.
func formatSecondsInterval(s string) (string, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return "", false
	}
	if n == 0 {
		return "0 (not set)", true
	}
	return humanDuration(time.Duration(n) * time.Second), true
}

// humanDuration writes a policy interval the way someone would say it. These
// are configured in whole days, hours or minutes almost without exception, so
// the common cases come out exact and anything odd falls back to Go's own
// rendering rather than being rounded into a lie.
func humanDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return quantity(int(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return quantity(int(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return quantity(int(d/time.Minute), "minute")
	case d%time.Second == 0:
		return quantity(int(d/time.Second), "second")
	default:
		return d.String()
	}
}

func quantity(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// HexDump renders a binary value for the detail popup, in the usual
// offset / hex / ASCII layout.
func HexDump(raw []byte) string {
	return strings.TrimRight(hex.Dump(raw), "\n")
}
