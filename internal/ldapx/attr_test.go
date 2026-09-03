package ldapx

import (
	"strings"
	"testing"
	"time"
)

func TestFormatGUID(t *testing.T) {
	// The first three fields are little-endian on the wire; the last two are
	// byte order as-is. A plain hex dump with dashes would get this wrong.
	raw := []byte{
		0x78, 0x56, 0x34, 0x12,
		0x34, 0x12,
		0x78, 0x56,
		0x12, 0x34,
		0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	}
	got := Format("objectGUID", raw)
	if want := "12345678-1234-5678-1234-56789abcdef0"; got.Text != want {
		t.Errorf("objectGUID = %q, want %q", got.Text, want)
	}
	if !got.Binary {
		t.Error("a rendered GUID is still a binary value")
	}
	// eDirectory spells the same thing "GUID".
	if e := Format("GUID", raw); e.Text != got.Text {
		t.Errorf("GUID = %q, want same as objectGUID %q", e.Text, got.Text)
	}
	// A wrong-length value must fall back rather than produce a bogus GUID.
	if short := Format("objectGUID", []byte{1, 2, 3}); !strings.HasPrefix(short.Text, "<binary,") {
		t.Errorf("short objectGUID = %q, want a binary description", short.Text)
	}
}

func TestFormatSID(t *testing.T) {
	// S-1-5-21-1004336348-1177238915-682003330-512
	raw := []byte{
		0x01,                               // revision
		0x05,                               // sub-authority count
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority 5, big-endian
		0x15, 0x00, 0x00, 0x00, // 21
		0xdc, 0xf4, 0xdc, 0x3b, // 1004336348
		0x83, 0x3d, 0x2b, 0x46, // 1177238915
		0x82, 0x8b, 0xa6, 0x28, // 682003330
		0x00, 0x02, 0x00, 0x00, // 512
	}
	got := Format("objectSid", raw)
	if want := "S-1-5-21-1004336348-1177238915-682003330-512"; got.Text != want {
		t.Errorf("objectSid = %q, want %q", got.Text, want)
	}
	if truncated := Format("objectSid", raw[:10]); !strings.HasPrefix(truncated.Text, "<binary,") {
		t.Errorf("truncated objectSid = %q, want a binary description", truncated.Text)
	}
}

func TestFormatGeneralizedTime(t *testing.T) {
	for _, in := range []string{
		"20240115103000Z",
		"20240115103000.0Z",
		"20240115103000.123456Z",
	} {
		got := Format("whenCreated", []byte(in))
		want := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC).Local().Format("2006-01-02 15:04:05 MST")
		if got.Text != want {
			t.Errorf("whenCreated %q = %q, want %q", in, got.Text, want)
		}
	}
	// Anything unparseable is shown as-is rather than swallowed.
	if got := Format("whenCreated", []byte("not a time")); got.Text != "not a time" {
		t.Errorf("unparseable time = %q, want it passed through", got.Text)
	}
}

func TestFormatFiletime(t *testing.T) {
	cases := map[string]string{
		"0":                   "0 (never / not set)",
		"9223372036854775807": "never expires",
		"133497882000000000": time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC).
			Local().Format("2006-01-02 15:04:05 MST"),
	}
	for in, want := range cases {
		if got := Format("pwdLastSet", []byte(in)); got.Text != want {
			t.Errorf("pwdLastSet %q = %q, want %q", in, got.Text, want)
		}
	}
}

func TestFormatUserAccountControl(t *testing.T) {
	if got := Format("userAccountControl", []byte("512")); got.Text != "512 (NORMAL_ACCOUNT)" {
		t.Errorf("uac 512 = %q", got.Text)
	}
	got := Format("userAccountControl", []byte("514"))
	if !strings.Contains(got.Text, "ACCOUNTDISABLE") {
		t.Errorf("uac 514 = %q, want it to name ACCOUNTDISABLE", got.Text)
	}
	if !strings.Contains(got.Text, "NORMAL_ACCOUNT") {
		t.Errorf("uac 514 = %q, want it to name NORMAL_ACCOUNT too", got.Text)
	}
}

func TestFormatTextAndBinaryFallback(t *testing.T) {
	if got := Format("cn", []byte("John Doe")); got.Text != "John Doe" || got.Binary {
		t.Errorf("cn = %+v, want plain text", got)
	}
	// Valid UTF-8 but full of control bytes is not something to print.
	if got := Format("description", []byte{0x01, 0x02, 0x03}); !got.Binary {
		t.Errorf("control bytes = %+v, want binary", got)
	}
	// An escape sequence is valid UTF-8 and would be obeyed by the terminal.
	if got := Format("description", []byte("\x1b[2J")); !got.Binary {
		t.Errorf("escape sequence = %+v, want binary", got)
	}
	// U+009B is the eight-bit CSI: valid UTF-8, two bytes, neither below 0x20.
	if got := Format("description", []byte("\u009b2J")); !got.Binary {
		t.Errorf("eight-bit CSI = %+v, want binary", got)
	}
	// Invalid UTF-8 is binary regardless of the attribute name.
	if got := Format("description", []byte{0xff, 0xfe, 0xfd}); !got.Binary {
		t.Errorf("invalid utf-8 = %+v, want binary", got)
	}
	// Known-binary attributes stay binary even when the bytes look like text.
	if got := Format("userCertificate", []byte("MIIB")); !got.Binary {
		t.Errorf("userCertificate = %+v, want binary", got)
	}
	// The ;binary transfer-option suffix must not defeat the name lookup.
	if got := Format("userCertificate;binary", []byte("MIIB")); !got.Binary {
		t.Errorf("userCertificate;binary = %+v, want binary", got)
	}
	// Newlines and tabs are legitimate in text attributes.
	if got := Format("description", []byte("line one\nline two")); got.Binary {
		t.Errorf("multi-line description = %+v, want text", got)
	}
	if got := Format("cn", []byte{0x41}); got.Text != "A" {
		t.Errorf("single byte = %q", got.Text)
	}
	if got := Format("userCertificate", []byte{0x00}); got.Text != "<binary, 1 byte>" {
		t.Errorf("singular byte count = %q", got.Text)
	}
}

// A DN never goes through Format, so SafeText is the only thing between a
// directory and the terminal.
func TestSafeText(t *testing.T) {
	unchanged := []string{
		"",
		"uid=jdoe,ou=People,dc=example,dc=com",
		"cn=Jörg Müller,dc=example,dc=com",
		"cn=one\ttwo,dc=x",
	}
	for _, s := range unchanged {
		if got := SafeText(s); got != s {
			t.Errorf("SafeText(%q) = %q, want it left alone", s, got)
		}
	}

	cases := map[string]string{
		"cn=\x1b[2Jx,dc=y":   "cn=�[2Jx,dc=y",
		"cn=\u009b2Jx,dc=y":  "cn=�2Jx,dc=y",
		"cn=a\x07b,dc=y":     "cn=a�b,dc=y",
		"cn=a\x7fb,dc=y":     "cn=a�b,dc=y",
		"cn=one\r\ntwo,dc=y": "cn=one\r\ntwo,dc=y",
	}
	for in, want := range cases {
		if got := SafeText(in); got != want {
			t.Errorf("SafeText(%q) = %q, want %q", in, got, want)
		}
	}
}
