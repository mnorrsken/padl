package ldapx

import (
	"strings"
	"testing"
)

// render is the shape most of these tests want: what the object pane would show
// for one value of one attribute.
func render(attr, value string) string {
	return Format(attr, []byte(value)).Text
}

// A name in two tables would mean one vendor's attribute quietly rendered by
// another's rules, and mergeRenderings would pick a winner without saying so.
func TestRenderingTablesDoNotCollide(t *testing.T) {
	tables := map[string]map[string]rendering{
		"common":     commonRenderings,
		"ad":         adRenderings,
		"exchange":   exchangeRenderings,
		"edirectory": edirectoryRenderings,
		"idm":        idmRenderings,
	}
	seen := map[string]string{}
	for table, entries := range tables {
		for name := range entries {
			if other, dup := seen[name]; dup {
				t.Errorf("%q is in both %s and %s", name, other, table)
				continue
			}
			seen[name] = table
		}
		// The tables are looked up by a lowercased name with options stripped,
		// so a key that is not already in that form can never match.
		for name := range entries {
			if got := baseAttrName(name); got != name {
				t.Errorf("%s key %q is not in lookup form (%q)", table, name, got)
			}
		}
	}
}

// The flag words, all against values read off the lab domain controller. Every
// one of these arrives as a signed decimal, and two of them are negative.
func TestActiveDirectoryFlagWords(t *testing.T) {
	cases := []struct{ attr, value, want string }{
		{"userAccountControl", "512", "512 (NORMAL_ACCOUNT)"},
		{"userAccountControl", "514", "514 (ACCOUNTDISABLE | NORMAL_ACCOUNT)"},
		{"userAccountControl", "66048", "66048 (NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD)"},
		{"groupType", "-2147483646", "-2147483646 (GLOBAL | SECURITY_ENABLED)"},
		{"groupType", "4", "4 (DOMAIN_LOCAL)"},
		{"instanceType", "4", "4 (WRITABLE)"},
		{"instanceType", "5", "5 (NC_HEAD | WRITABLE)"},
		{"systemFlags", "-1946157056", "-1946157056 (DOMAIN_DISALLOW_MOVE | DOMAIN_DISALLOW_RENAME | DISALLOW_DELETE)"},
		{"sAMAccountType", "805306368", "805306368 (SAM_USER_OBJECT)"},
		{"sAMAccountType", "268435456", "268435456 (SAM_GROUP_OBJECT)"},
		{"msDS-Behavior-Version", "4", "4 (Windows Server 2008 R2)"},
		{"primaryGroupID", "513", "513 (Domain Users)"},
		{"msDS-SupportedEncryptionTypes", "28", "28 (RC4-HMAC | AES128-CTS-HMAC-SHA1-96 | AES256-CTS-HMAC-SHA1-96)"},
		{"searchFlags", "1", "1 (INDEXED)"},
	}
	for _, c := range cases {
		if got := render(c.attr, c.value); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.attr, c.value, got, c.want)
		}
	}

	// A bit nobody has named is still reported rather than dropped, because a
	// missing flag is indistinguishable from a flag that is not set.
	if got := render("userAccountControl", "536870912"); !strings.Contains(got, "0x20000000") {
		t.Errorf("an unnamed bit should be shown as hex, got %q", got)
	}
	// Something that is not a number at all falls through untouched.
	if got := render("userAccountControl", "banana"); got != "banana" {
		t.Errorf("unparseable flag word = %q, want it left alone", got)
	}
	// An enumeration with no entry for the value says nothing rather than
	// inventing a name.
	if got := render("sAMAccountType", "12345"); got != "12345" {
		t.Errorf("unknown sAMAccountType = %q, want the bare number", got)
	}
}

// The domain password policy, which AD stores as negative FILETIME intervals.
// A 30-minute lockout reads -18000000000 on the wire.
func TestActiveDirectoryDurations(t *testing.T) {
	cases := []struct{ attr, value, want string }{
		{"maxPwdAge", "-9223372036854775808", "never"},
		{"forceLogoff", "-9223372036854775808", "never"},
		{"minPwdAge", "-864000000000", "1 day"},
		{"maxPwdAge", "-36288000000000", "42 days"},
		{"lockoutDuration", "-18000000000", "30 minutes"},
		{"lockOutObservationWindow", "-18000000000", "30 minutes"},
		{"lockoutDuration", "-36000000000", "1 hour"},
		{"lockoutDuration", "0", "0 (not set)"},
	}
	for _, c := range cases {
		if got := render(c.attr, c.value); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.attr, c.value, got, c.want)
		}
	}

	// These are stored negative. A positive one is not an interval, and saying
	// "30 minutes" for it would be worse than saying nothing.
	if got := render("lockoutDuration", "18000000000"); got != "18000000000" {
		t.Errorf("a positive interval = %q, want it left alone", got)
	}
}

func TestActiveDirectoryTimestamps(t *testing.T) {
	// A FILETIME renders as a date; what matters is that the eighteen-digit
	// number does not survive.
	got := render("pwdLastSet", "134329234739510944")
	if strings.HasPrefix(got, "134") {
		t.Errorf("pwdLastSet = %q, want it rendered", got)
	}
	if !strings.HasPrefix(got, "2026-") {
		t.Errorf("pwdLastSet = %q, want a 2026 date", got)
	}
	if got := render("accountExpires", "9223372036854775807"); got != "never expires" {
		t.Errorf("accountExpires max = %q", got)
	}
	if got := render("lastLogon", "0"); got != "0 (never / not set)" {
		t.Errorf("lastLogon 0 = %q", got)
	}
	// whenCreated is the other spelling, and is generalizedTime.
	if got := render("whenCreated", "20260903153753.0Z"); strings.HasSuffix(got, "Z") {
		t.Errorf("whenCreated = %q, want it rendered", got)
	}
}

func TestActiveDirectoryIdentifiersAreBinary(t *testing.T) {
	guid := []byte{
		0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	for _, attr := range []string{"objectGUID", "mS-DS-ConsistencyGuid", "schemaIDGUID", "invocationId"} {
		v := Format(attr, guid)
		if v.Text != "12345678-1234-5678-1234-56789abcdef0" {
			t.Errorf("%s = %q", attr, v.Text)
		}
		if !v.Binary {
			t.Errorf("%s should stay a binary value", attr)
		}
	}

	sid := []byte{
		0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x15, 0x00, 0x00, 0x00, 0xdc, 0xf4, 0xdc, 0x3b,
		0x83, 0x3d, 0x2b, 0x46, 0x82, 0x8b, 0xa6, 0x28,
		0x00, 0x02, 0x00, 0x00,
	}
	for _, attr := range []string{"objectSid", "sIDHistory", "tokenGroups"} {
		if got := Format(attr, sid).Text; !strings.HasPrefix(got, "S-1-5-21-") {
			t.Errorf("%s = %q", attr, got)
		}
	}

	// A value that is not the right length falls through to the hex dump rather
	// than being rendered from whatever bytes happen to be there.
	if got := Format("objectGUID", []byte{1, 2, 3}).Text; !strings.HasPrefix(got, "<binary,") {
		t.Errorf("short objectGUID = %q", got)
	}
}

func TestExchangeRecipientTypes(t *testing.T) {
	cases := []struct{ attr, value, want string }{
		{"msExchRecipientTypeDetails", "1", "1 (UserMailbox)"},
		{"msExchRecipientTypeDetails", "16", "16 (RoomMailbox)"},
		{"msExchRecipientTypeDetails", "32", "32 (EquipmentMailbox)"},
		{"msExchRecipientTypeDetails", "2147483648", "2147483648 (RemoteUserMailbox)"},
		{"msExchRecipientDisplayType", "0", "0 (MailboxUser)"},
		{"msExchRecipientDisplayType", "1073741824", "1073741824 (ACLableMailboxUser)"},
		{"msExchRecipientDisplayType", "-2147483642", "-2147483642 (SyncedMailboxUser)"},
		{"msExchRemoteRecipientType", "1", "1 (ProvisionMailbox)"},
		{"msExchRemoteRecipientType", "3", "3 (ProvisionMailbox | ProvisionArchive)"},
	}
	for _, c := range cases {
		if got := render(c.attr, c.value); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.attr, c.value, got, c.want)
		}
	}
}

// The case of the scheme is the whole point: SMTP: is the reply address and
// smtp: is an alias. The address itself is kept, because this is a value people
// copy out of the pane.
func TestProxyAddressesAreLabelled(t *testing.T) {
	cases := []struct{ value, want string }{
		{"SMTP:jdoe@example.com", "SMTP:jdoe@example.com (primary SMTP)"},
		{"smtp:john.doe@example.com", "smtp:john.doe@example.com (SMTP alias)"},
		{"X500:/o=x/ou=y", "X500:/o=x/ou=y (primary X.500)"},
		{"sip:jdoe@example.com", "sip:jdoe@example.com (SIP alias)"},
	}
	for _, c := range cases {
		if got := render("proxyAddresses", c.value); got != c.want {
			t.Errorf("%q = %q, want %q", c.value, got, c.want)
		}
	}
	// A scheme nobody recognises is left exactly as it is.
	if got := render("proxyAddresses", "zzz:something"); got != "zzz:something" {
		t.Errorf("unknown scheme = %q, want it untouched", got)
	}
	if got := render("proxyAddresses", "no-colon-here"); got != "no-colon-here" {
		t.Errorf("no scheme = %q, want it untouched", got)
	}
}

func TestLogonHours(t *testing.T) {
	all := make([]byte, 21)
	for i := range all {
		all[i] = 0xff
	}
	if got := Format("logonHours", all); got.Text != "all hours" {
		t.Errorf("full week = %q", got.Text)
	}
	if got := Format("logonHours", make([]byte, 21)); got.Text != "no hours (logon blocked)" {
		t.Errorf("empty week = %q", got.Text)
	}
	partial := make([]byte, 21)
	partial[0] = 0x0f
	if got := Format("logonHours", partial); got.Text != "4 of 168 hours" {
		t.Errorf("partial week = %q", got.Text)
	}
	// The wrong length is not a logonHours value at all.
	if got := Format("logonHours", []byte{0xff}); !strings.HasPrefix(got.Text, "<binary,") {
		t.Errorf("short logonHours = %q", got.Text)
	}
}

func TestEDirectoryTimesAndIntervals(t *testing.T) {
	// eDirectory hands its Time syntax to LDAP as generalizedTime.
	for _, attr := range []string{
		"loginTime", "lastLoginTime", "passwordExpirationTime",
		"loginExpirationTime", "pwdChangedTime",
	} {
		got := render(attr, "20260903153753Z")
		if strings.HasSuffix(got, "Z") {
			t.Errorf("%s = %q, want it rendered", attr, got)
		}
		if !strings.HasPrefix(got, "2026-09-03") {
			t.Errorf("%s = %q, want the date", attr, got)
		}
	}

	// Intervals are plain second counts, unlike AD's negative FILETIME ticks.
	cases := []struct{ attr, value, want string }{
		{"passwordExpirationInterval", "7776000", "90 days"},
		{"loginIntruderResetInterval", "1800", "30 minutes"},
		{"intruderAttemptResetInterval", "0", "0 (not set)"},
	}
	for _, c := range cases {
		if got := render(c.attr, c.value); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.attr, c.value, got, c.want)
		}
	}

	// The eDirectory GUID is the same 16-byte shape.
	guid := []byte{
		0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	if v := Format("GUID", guid); v.Text != "12345678-1234-5678-1234-56789abcdef0" || !v.Binary {
		t.Errorf("eDirectory GUID = %+v", v)
	}
}

// The two values Micro Focus decodes by hand in KB 7006280, which is what the
// implementation was written from. Both carry 0x40000000, and the same low bits
// have to come out differently because the protected name differs.
func TestEDirectoryACLDocumentedExamples(t *testing.T) {
	trustee := "cn=MyOrg,cn=User Management,cn=Role Based Service,ou=ENT,o=MyOrg"

	// 1073741855 is 0x4000001F: every entry right, plus iManager RBS.
	got := render("ACL", "1073741855#subtree#"+trustee+"#[Entry Rights]")
	want := "[Entry Rights]: browse | create | delete | rename | supervisor | iManager RBS · subtree · " + trustee
	if got != want {
		t.Errorf("entry rights =\n  %q\nwant\n  %q", got, want)
	}

	// 1073741863 is 0x40000027. The same 0x20 that was nothing in the entry
	// reading is supervisor here, and 0x04 is write rather than delete.
	got = render("ACL", "1073741863#subtree#"+trustee+"#cn")
	want = "cn: compare | read | write | supervisor | iManager RBS · subtree · " + trustee
	if got != want {
		t.Errorf("attribute rights =\n  %q\nwant\n  %q", got, want)
	}
}

// The bit tables overlap in value and differ in meaning, so which one is used
// has to follow the fourth field and nothing else.
func TestEDirectoryACLRightsDependOnTheProtectedName(t *testing.T) {
	cases := []struct{ value, want string }{
		// 0x04 is delete over an entry and write over an attribute.
		{"4#entry#[Public]#[Entry Rights]", "[Entry Rights]: delete · entry · [Public]"},
		{"4#entry#[Public]#cn", "cn: write · entry · [Public]"},
		// 0x10 is supervisor over an entry but has no attribute meaning, so it
		// has to show as the raw bit rather than be dropped.
		{"16#entry#[Public]#[Entry Rights]", "[Entry Rights]: supervisor · entry · [Public]"},
		{"16#entry#[Public]#cn", "cn: 0x10 · entry · [Public]"},
		// 0x20 is the other way round.
		{"32#entry#[Public]#cn", "cn: supervisor · entry · [Public]"},
		// [All Attributes Rights] reads as attribute rights, not entry rights.
		{"6#subtree#[Root]#[All Attributes Rights]", "[All Attributes Rights]: read | write · subtree · [Root]"},
		// The high flags mean the same in either reading.
		{"536870916#subtree#cn=dyn,o=example#cn", "cn: write | dynamic group members · subtree · cn=dyn,o=example"},
		// A trustee with no rights at all is a real thing to find.
		{"0#entry#[Self]#[Entry Rights]", "[Entry Rights]: no rights · entry · [Self]"},
	}
	for _, c := range cases {
		if got := render("ACL", c.value); got != c.want {
			t.Errorf("%q =\n  %q\nwant\n  %q", c.value, got, c.want)
		}
	}
}

// Values read off a live eDirectory 9.3.3 tree. Two of them are the reason the
// rights table has to follow the protected name: the same object carries
// supervisor as 16 over the entry and as 32 over the attributes, so a single
// table would have got one of them wrong.
func TestEDirectoryACLLiveValues(t *testing.T) {
	cases := []struct{ value, want string }{
		{"16#subtree#cn=edir1,o=padl#[Entry Rights]",
			"[Entry Rights]: supervisor · subtree · cn=edir1,o=padl"},
		{"32#subtree#cn=edir1,o=padl#[All Attributes Rights]",
			"[All Attributes Rights]: supervisor · subtree · cn=edir1,o=padl"},
		{"31#entry#cn=edir1,o=padl#[Entry Rights]",
			"[Entry Rights]: browse | create | delete | rename | supervisor · entry · cn=edir1,o=padl"},
		{"47#entry#cn=edir1,o=padl#[All Attributes Rights]",
			"[All Attributes Rights]: compare | read | write | add self | supervisor · entry · cn=edir1,o=padl"},
		{"2#entry#[Public]#hostServer",
			"hostServer: read · entry · [Public]"},
		{"6#entry#cn=admin,o=padl#loginScript",
			"loginScript: read | write · entry · cn=admin,o=padl"},
		// A trustee DN with spaces in it, which the split must not disturb.
		{"2#subtree#cn=SAS Service - edir1,o=padl#[All Attributes Rights]",
			"[All Attributes Rights]: read · subtree · cn=SAS Service - edir1,o=padl"},
		// The tree writes 47 over [Entry Rights] as well, where 0x20 has no
		// entry meaning. Showing the bit is the honest answer: claiming
		// supervisor for it would be wrong, and dropping it would read as a
		// right that is not granted.
		{"47#entry#cn=edir1,o=padl#[Entry Rights]",
			"[Entry Rights]: browse | create | delete | rename | 0x20 · entry · cn=edir1,o=padl"},
	}
	for _, c := range cases {
		if got := render("ACL", c.value); got != c.want {
			t.Errorf("%q =\n  %q\nwant\n  %q", c.value, got, c.want)
		}
	}
}

// "acl" is a plausible attribute name elsewhere, and a value that is not this
// syntax must not be reported as a permission that does not exist.
func TestEDirectoryACLLeavesAnythingElseAlone(t *testing.T) {
	for _, in := range []string{
		"not-an-acl",
		"1#nowhere#cn=x,o=y#cn", // scope is neither entry nor subtree
		"abc#entry#cn=x,o=y#cn", // privileges are not a number
		"-1#entry#cn=x,o=y#cn",  // nor a mask
		"1#entry#cn=x,o=y",      // three fields
		"1#entry#cn=x,o=y#cn#extra",
		"1#entry##cn",       // no trustee
		"1#entry#cn=x,o=y#", // no protected name
	} {
		if got := render("ACL", in); got != in {
			t.Errorf("%q = %q, want it left alone", in, got)
		}
	}
}

// DirXML-Associations is the first thing anyone reads when an object is not
// syncing, and raw it is three fields run together. References disagree about
// whether the driver DN or the state comes first, so both orders have to work.
func TestDirXMLAssociations(t *testing.T) {
	want := "associated · cn=ADDriver,cn=DriverSet,o=services · f1a2b3"
	for _, in := range []string{
		"cn=ADDriver,cn=DriverSet,o=services#2#f1a2b3",
		"2#cn=ADDriver,cn=DriverSet,o=services#f1a2b3",
	} {
		if got := render("DirXML-Associations", in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}

	if got := render("DirXML-Associations", "0#cn=Driver,o=services#abc"); !strings.HasPrefix(got, "disabled ") {
		t.Errorf("state 0 = %q, want it named disabled", got)
	}

	// Anything that is not three fields, or has no DN among them, is left alone
	// rather than guessed at.
	for _, in := range []string{
		"just-a-string",
		"one#two",
		"1#2#3",
	} {
		if got := render("DirXML-Associations", in); got != in {
			t.Errorf("%q = %q, want it left alone", in, got)
		}
	}

	if got := render("DirXML-State", "2"); got != "2 (associated)" {
		t.Errorf("DirXML-State = %q", got)
	}
	if got := render("DirXML-DriverStartOption", "2"); got != "2 (auto start)" {
		t.Errorf("DirXML-DriverStartOption = %q", got)
	}
}

// DirXML-PasswordSyncStatus is what you read when a new password works in one
// connected system and not another, and raw it is sixty-odd characters of
// fixed-width fields run together with no separators.
func TestDirXMLPasswordSyncStatus(t *testing.T) {
	// NetIQ's own worked example, from the Password Management Guide.
	documented := "39DB7DED8436EE4DF38039DB7DED843620140325141422721000000000001Code(-8032) Operation vetoed by policy"
	want := "WARNING · 2014-03-25 14:14:22.721 · Code(-8032) Operation vetoed by policy · driver 39DB7DED8436EE4DF38039DB7DED8436"
	if got := render("DirXML-PasswordSyncStatus", documented); got != want {
		t.Errorf("documented example =\n  %q\nwant\n  %q", got, want)
	}

	guid := "39DB7DED8436EE4DF38039DB7DED8436"
	stamp := "20260903101530500"
	value := func(code, message string) string { return guid + stamp + "00000000" + code + message }

	codes := map[string]string{
		"0000": "ERROR", "0001": "WARNING", "0002": "RETRY",
		"0003": "FATAL", "0004": "SUCCESS", "0005": "PENDING",
	}
	for code, name := range codes {
		got := render("DirXML-PasswordSyncStatus", value(code, ""))
		want := name + " · 2026-09-03 10:15:30.500 · driver " + guid
		if got != want {
			t.Errorf("code %s = %q, want %q", code, got, want)
		}
	}

	// A message is kept as the server wrote it.
	if got := render("DirXML-PasswordSyncStatus", value("0005", "Driver not running")); got !=
		"PENDING · 2026-09-03 10:15:30.500 · Driver not running · driver "+guid {
		t.Errorf("with a message = %q", got)
	}

	// The timestamp carries no zone and the documentation does not say which one
	// it is, so it is reformatted where it stands rather than shifted by a guess.
	if got := render("DirXML-PasswordSyncStatus", value("0004", "")); !strings.Contains(got, "10:15:30.500") {
		t.Errorf("the timestamp should read back unmoved, got %q", got)
	}
}

// A Fan-Out driver puts its instance GUID after the driver's, which is the only
// difference between the two layouts and why the value is 93 characters there.
func TestDirXMLPasswordSyncStatusFanOut(t *testing.T) {
	driver := "39DB7DED8436EE4DF38039DB7DED8436"
	instance := "AABBCCDDEEFF00112233445566778899"
	value := driver + instance + "20260903101530500" + "00000000" + "0004"
	if len(value) != 93 {
		t.Fatalf("the documented Fan-Out length is 93, this test's value is %d", len(value))
	}

	want := "SUCCESS · 2026-09-03 10:15:30.500 · driver " + driver + " · instance " + instance
	if got := render("DirXML-PasswordSyncStatus", value); got != want {
		t.Errorf("fan-out =\n  %q\nwant\n  %q", got, want)
	}
}

// Nothing that is not this shape may be reported as a sync result.
func TestDirXMLPasswordSyncStatusLeavesAnythingElseAlone(t *testing.T) {
	guid := "39DB7DED8436EE4DF38039DB7DED8436"
	for _, in := range []string{
		"nonsense",
		"",
		// A status code outside the six.
		guid + "20260903101530500" + "00000000" + "0009" + "unknown",
		// A timestamp that is not a date.
		guid + "20261303101530500" + "00000000" + "0004",
		// A driver GUID that is not hex.
		"zzDB7DED8436EE4DF38039DB7DED8436" + "20260903101530500" + "00000000" + "0004",
		// Too short to hold the fixed fields.
		guid + "20260903101530500" + "0000",
	} {
		if got := render("DirXML-PasswordSyncStatus", in); got != in {
			t.Errorf("%q = %q, want it left alone", in, got)
		}
	}
}

// Whatever the rendering, the bytes the directory sent are kept, because the
// hex dump and any future "copy raw" read them rather than the text.
func TestRenderedValuesKeepTheirRaw(t *testing.T) {
	raw := []byte("512")
	v := Format("userAccountControl", raw)
	if string(v.Raw) != "512" {
		t.Errorf("Raw = %q, want the value as it arrived", v.Raw)
	}
	if v.Binary {
		t.Error("a flag word is text, not a rendering of bytes")
	}
}
