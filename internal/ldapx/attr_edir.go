package ldapx

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// eDirectory and NetIQ Identity Manager attribute rendering.
//
// eDirectory maps its own syntaxes onto LDAP ones, so most of what needs help
// here is either a time it writes as generalizedTime, an interval it writes as
// a plain second count, or a value where several fields have been packed into
// one string with "#" between them.
//
// What is deliberately *not* decoded: the Net Address syntax behind
// networkAddress, whose field order differs between references. A rendering of
// it that is confidently wrong would be worse than the raw value.

var edirectoryRenderings = map[string]rendering{
	// Times. eDirectory hands these to LDAP as generalizedTime.
	"logintime":              decodeText(formatGeneralizedTime),
	"lastlogintime":          decodeText(formatGeneralizedTime),
	"passwordexpirationtime": decodeText(formatGeneralizedTime),
	"loginexpirationtime":    decodeText(formatGeneralizedTime),
	"pwdchangedtime":         decodeText(formatGeneralizedTime),
	"expirationtime":         decodeText(formatGeneralizedTime),
	"loginintruderresettime": decodeText(formatGeneralizedTime),
	"lockoutresettime":       decodeText(formatGeneralizedTime),

	// Intervals, in whole seconds.
	"passwordexpirationinterval":   decodeText(formatSecondsInterval),
	"loginintruderresetinterval":   decodeText(formatSecondsInterval),
	"intruderattemptresetinterval": decodeText(formatSecondsInterval),
	"intruderlockoutresetinterval": decodeText(formatSecondsInterval),

	// The GUID, which is the same 16-byte shape Microsoft uses.
	"guid": decodeBytes(formatGUID),

	// Access control, four fields packed into one string.
	"acl": decodeText(formatEDirectoryACL),
}

// The eDirectory ACL value is
//
//	privileges # scope # trustee DN # protected attribute name
//
// and the privileges are a bitmask whose meaning depends on the fourth field:
// "[Entry Rights]" makes them rights over the object, anything else — a named
// attribute, or "[All Attributes Rights]" — makes them rights over a property.
// The same bit is Create in one reading and Write in the other, so getting this
// wrong would misreport who can do what.
//
// Two worked examples from the vendor's own note, both of which the tests use:
//
//	1073741855#subtree#cn=MyOrg,…,o=MyOrg#[Entry Rights]   0x4000001F
//	1073741863#subtree#cn=MyOrg,…,o=MyOrg#cn               0x40000027
//
// Sources: Micro Focus KB 7006280 "What does the numeric value of ACL mean in
// an LDAP export?", the LDAP Explorer Novell ACL editor manual, and LDAPWiki's
// Object ACL and eDirectory Privileges pages.

// edirEntryRights apply when the protected name is "[Entry Rights]".
var edirEntryRights = []flag{
	{0x00000001, "browse"},
	{0x00000002, "create"},
	{0x00000004, "delete"},
	{0x00000008, "rename"},
	{0x00000010, "supervisor"},
	{0x00000040, "inheritance control"},
}

// edirAttrRights apply to every other protected name. Note that supervisor is
// 0x20 here and 0x10 in the entry table: the same number decodes differently
// depending on the field beside it.
var edirAttrRights = []flag{
	{0x00000001, "compare"},
	{0x00000002, "read"},
	{0x00000004, "write"},
	{0x00000008, "add self"},
	{0x00000020, "supervisor"},
	{0x00000040, "inheritance control"},
}

// edirACLFlags are set alongside either set of rights and mean the same thing
// in both. They are why a real ACL value is a billion rather than a handful.
var edirACLFlags = []flag{
	{0x20000000, "dynamic group members"},
	{0x40000000, "iManager RBS"},
}

// formatEDirectoryACL renders one access control entry.
//
// The guards are the point: an attribute called "acl" on some other directory,
// or a value that is not this syntax, has to fall through untouched rather than
// be reported as a permission that does not exist. A value only renders when it
// has all four fields, a privilege mask that is a number, and a scope that is
// one of the two words eDirectory uses.
func formatEDirectoryACL(s string) (string, bool) {
	parts := strings.Split(s, "#")
	if len(parts) != 4 {
		return "", false
	}
	privileges := strings.TrimSpace(parts[0])
	scope := strings.TrimSpace(parts[1])
	trustee := strings.TrimSpace(parts[2])
	protected := strings.TrimSpace(parts[3])

	if trustee == "" || protected == "" {
		return "", false
	}
	if !strings.EqualFold(scope, "entry") && !strings.EqualFold(scope, "subtree") {
		return "", false
	}
	n, err := strconv.ParseInt(privileges, 10, 64)
	if err != nil || n < 0 || n > math.MaxUint32 {
		return "", false
	}

	rights := edirAttrRights
	if strings.EqualFold(protected, "[Entry Rights]") {
		rights = edirEntryRights
	}
	set := namedBits(uint32(n), rights, edirACLFlags)
	if len(set) == 0 {
		set = []string{"no rights"}
	}

	return fmt.Sprintf("%s: %s · %s · %s",
		protected, strings.Join(set, " | "), strings.ToLower(scope), trustee), true
}

// idmRenderings are NetIQ Identity Manager's. DirXML-Associations is the one
// worth having: it is the first thing anybody looks at when an object is not
// syncing, and raw it is three fields run together with no clue which is which.
var idmRenderings = map[string]rendering{
	"dirxml-associations":       decodeText(formatDirXMLAssociation),
	"dirxml-state":              decodeText(enumeration(dirXMLAssociationStates)),
	"dirxml-driverstartoption":  decodeText(enumeration(dirXMLStartOptions)),
	"dirxml-drivertracelevel":   decodeText(enumeration(dirXMLTraceLevels)),
	"dirxml-passwordsyncstatus": decodeText(formatDirXMLPasswordSyncStatus),
}

// DirXML-PasswordSyncStatus records what happened the last time a password
// change was pushed to a driver. It is the attribute you read when somebody
// says their new password works in one system and not another, and raw it is a
// run of sixty-odd characters with no separators at all:
//
//	39DB7DED8436EE4DF38039DB7DED843620140325141422721000000000001Code(-8032) Operation vetoed by policy
//
// Fixed-width fields, in order: 32 characters of driver GUID, 17 of timestamp
// as yyyyMMddHHmmssSSS, 8 of zeroes, a 4-digit status code, then the message if
// there is one. A Fan-Out driver appends the instance GUID after the driver's,
// which is why the value is 93 characters there rather than 61.
//
// Source: NetIQ Identity Manager Password Management Guide, "Checking the
// Password Synchronization Status for a User". The example above is theirs and
// is pinned as a test.
var dirXMLPasswordSyncStatuses = map[string]string{
	"0000": "ERROR",
	"0001": "WARNING",
	"0002": "RETRY",
	"0003": "FATAL",
	"0004": "SUCCESS",
	"0005": "PENDING",
}

const (
	syncStatusGUIDLen = 32
	syncStatusTimeLen = 17
	syncStatusPadLen  = 8
	syncStatusCodeLen = 4
)

// formatDirXMLPasswordSyncStatus renders one status value.
//
// The ordinary and Fan-Out layouts differ only by a second GUID, and nothing in
// the value says which it is, so both are tried. Confusing them is close to
// impossible in practice: either reading has to yield a timestamp that is a
// real date and a status code that is one of the six, and a GUID's first
// seventeen characters are hex rather than digits.
func formatDirXMLPasswordSyncStatus(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, guids := range []int{1, 2} {
		if text, ok := parsePasswordSyncStatus(s, guids); ok {
			return text, true
		}
	}
	return "", false
}

func parsePasswordSyncStatus(s string, guids int) (string, bool) {
	if len(s) < guids*syncStatusGUIDLen+syncStatusTimeLen+syncStatusPadLen+syncStatusCodeLen {
		return "", false
	}

	off := 0
	ids := make([]string, 0, guids)
	for i := 0; i < guids; i++ {
		id := s[off : off+syncStatusGUIDLen]
		if !isHex(id) {
			return "", false
		}
		ids = append(ids, id)
		off += syncStatusGUIDLen
	}

	when, ok := parseSyncStatusTime(s[off : off+syncStatusTimeLen])
	if !ok {
		return "", false
	}
	off += syncStatusTimeLen

	// Documented as eight zeroes. Requiring digits rather than zeroes exactly
	// leaves room for a field that turns out to mean something, while keeping
	// the signature strong enough that ordinary text cannot match it.
	if !isDigits(s[off : off+syncStatusPadLen]) {
		return "", false
	}
	off += syncStatusPadLen

	status, ok := dirXMLPasswordSyncStatuses[s[off:off+syncStatusCodeLen]]
	if !ok {
		return "", false
	}
	off += syncStatusCodeLen

	out := []string{status, when}
	if message := strings.TrimSpace(s[off:]); message != "" {
		out = append(out, message)
	}
	out = append(out, "driver "+ids[0])
	if len(ids) > 1 {
		out = append(out, "instance "+ids[1])
	}
	return strings.Join(out, " · "), true
}

// parseSyncStatusTime reformats yyyyMMddHHmmssSSS without moving it.
//
// The field carries no zone and the documentation does not say which one it is
// in, so converting to local time would shift a timestamp by a guess. The
// digits are shown back as they arrived, only readable.
func parseSyncStatusTime(s string) (string, bool) {
	if !isDigits(s) {
		return "", false
	}
	t, err := time.Parse("20060102150405.000", s[:14]+"."+s[14:])
	if err != nil {
		return "", false
	}
	return t.Format("2006-01-02 15:04:05.000"), true
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return len(s) > 0
}

// dirXMLAssociationStates are the association states an object can be in with a
// driver. "associated" is the one that means it is working.
var dirXMLAssociationStates = map[int64]string{
	0: "disabled",
	1: "processing",
	2: "associated",
	3: "pending",
	4: "manual",
	5: "migrate",
}

var dirXMLStartOptions = map[int64]string{
	0: "disabled",
	1: "manual",
	2: "auto start",
}

var dirXMLTraceLevels = map[int64]string{
	0: "off",
	1: "driver messages",
	2: "driver and engine messages",
	3: "plus XML documents",
	4: "plus DirXML script tracing",
	5: "plus rule evaluation",
}

// formatDirXMLAssociation renders one DirXML-Associations value.
//
// The value packs three fields into eDirectory's Path syntax, separated by "#":
// the driver's DN, the association state, and the key the connected system
// knows the object by. References disagree about which order the first two come
// in, so rather than pick one, this identifies them by shape — the state is the
// field that is a small number, the driver is the field that is a DN — and
// reports nothing if it cannot tell. Getting this wrong would mean naming the
// wrong driver in the one place people look when sync is broken.
func formatDirXMLAssociation(s string) (string, bool) {
	parts := strings.Split(s, "#")
	if len(parts) != 3 {
		return "", false
	}

	state, driver, key := -1, "", ""
	for _, p := range parts {
		switch {
		case state < 0 && isAssociationState(p):
			state, _ = strconv.Atoi(strings.TrimSpace(p))
		case driver == "" && strings.Contains(p, "="):
			driver = strings.TrimSpace(p)
		default:
			key = strings.TrimSpace(p)
		}
	}
	if state < 0 || driver == "" {
		return "", false
	}

	name := dirXMLAssociationStates[int64(state)]
	if name == "" {
		name = "state " + strconv.Itoa(state)
	}
	if key == "" {
		return fmt.Sprintf("%s · %s", name, driver), true
	}
	return fmt.Sprintf("%s · %s · %s", name, driver, key), true
}

func isAssociationState(s string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	_, ok := dirXMLAssociationStates[int64(n)]
	return ok
}
