package ldif

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mnorrsken/padl/internal/ldapx"
)

func attr(name string, values ...string) ldapx.Attribute {
	a := ldapx.Attribute{Name: name}
	for _, v := range values {
		a.Values = append(a.Values, []byte(v))
	}
	return a
}

func TestWriteEntry(t *testing.T) {
	e := &ldapx.Entry{
		DN: "uid=jdoe,ou=People,dc=example,dc=com",
		Attributes: []ldapx.Attribute{
			attr("objectClass", "top", "inetOrgPerson"),
			attr("uid", "jdoe"),
			attr("cn", "John Doe"),
		},
	}

	got := String(e)
	want := strings.Join([]string{
		"dn: uid=jdoe,ou=People,dc=example,dc=com",
		"objectClass: top",
		"objectClass: inetOrgPerson",
		"uid: jdoe",
		"cn: John Doe",
	}, "\n")
	if got != want {
		t.Errorf("String() =\n%s\n\nwant\n%s", got, want)
	}
}

// Operational attributes are the server's own bookkeeping; an LDIF carrying
// them cannot be fed back in.
func TestWriteEntrySkipsOperationalAttributes(t *testing.T) {
	e := &ldapx.Entry{
		DN: "uid=jdoe,dc=example,dc=com",
		Attributes: []ldapx.Attribute{
			attr("uid", "jdoe"),
			{Name: "createTimestamp", Values: [][]byte{[]byte("20240115103000Z")}, Operational: true},
		},
	}
	if got := String(e); strings.Contains(got, "createTimestamp") {
		t.Errorf("operational attribute made it into the LDIF:\n%s", got)
	}
}

func TestNeedsBase64(t *testing.T) {
	encoded := map[string]string{
		"leading space":     " hello",
		"leading colon":     ":hello",
		"leading less-than": "<hello",
		"trailing space":    "hello ",
		"embedded newline":  "one\ntwo",
		"carriage return":   "one\rtwo",
		"non-ascii":         "Jörg",
	}
	for name, v := range encoded {
		if !needsBase64([]byte(v)) {
			t.Errorf("%s (%q) should be base64-encoded", name, v)
		}
	}

	plain := []string{"hello", "John Doe", "a:b", "cn=x,dc=y", "", "hello world!"}
	for _, v := range plain {
		if needsBase64([]byte(v)) {
			t.Errorf("%q does not need encoding", v)
		}
	}

	// Invalid UTF-8 must always be encoded.
	if !needsBase64([]byte{0xff, 0xfe}) {
		t.Error("invalid UTF-8 must be base64-encoded")
	}
}

func TestBase64ValuesRoundTrip(t *testing.T) {
	value := "Jörg Müller"
	e := &ldapx.Entry{DN: "cn=x,dc=y", Attributes: []ldapx.Attribute{attr("cn", value)}}

	got := String(e)
	if !strings.Contains(got, "cn:: ") {
		t.Fatalf("a non-ASCII value should use the :: form:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "cn:: ") {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "cn:: "))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if string(decoded) != value {
			t.Errorf("round trip gave %q, want %q", decoded, value)
		}
	}
}

// RFC 2849 folds at 76 columns with a single leading space on continuations.
func TestFoldingIsReversible(t *testing.T) {
	long := strings.Repeat("x", 300)
	e := &ldapx.Entry{DN: "cn=x,dc=y", Attributes: []ldapx.Attribute{attr("description", long)}}

	got := String(e)
	var body []string
	for _, line := range strings.Split(got, "\n") {
		if len(line) > LineWidth {
			t.Errorf("line exceeds %d columns: %q", LineWidth, line)
		}
		body = append(body, line)
	}

	// Unfold the way a reader does: join continuations, dropping one space.
	var rebuilt strings.Builder
	for _, line := range body {
		if strings.HasPrefix(line, " ") {
			rebuilt.WriteString(line[1:])
			continue
		}
		if rebuilt.Len() > 0 {
			rebuilt.WriteString("\n")
		}
		rebuilt.WriteString(line)
	}
	if !strings.Contains(rebuilt.String(), "description: "+long) {
		t.Errorf("unfolding did not recover the value:\n%s", rebuilt.String())
	}
}

func TestWriteEntriesHasAVersionHeader(t *testing.T) {
	var b strings.Builder
	entries := []ldapx.Entry{
		{DN: "dc=example,dc=com", Attributes: []ldapx.Attribute{attr("dc", "example")}},
		{DN: "ou=People,dc=example,dc=com", Attributes: []ldapx.Attribute{attr("ou", "People")}},
	}
	if err := WriteEntries(&b, entries); err != nil {
		t.Fatalf("WriteEntries: %v", err)
	}
	got := b.String()
	if !strings.HasPrefix(got, "version: 1\n\n") {
		t.Errorf("an LDIF document starts with a version header:\n%s", got)
	}
	if n := strings.Count(got, "dn: "); n != 2 {
		t.Errorf("got %d records, want 2:\n%s", n, got)
	}
	// Records are separated by a blank line.
	if !strings.Contains(got, "dc: example\n\ndn: ou=People") {
		t.Errorf("records are not blank-line separated:\n%s", got)
	}
}

func TestComment(t *testing.T) {
	got := Comment("from %s\nat %s", "ldap://example", "now")
	if got != "# from ldap://example\n# at now\n" {
		t.Errorf("Comment() = %q", got)
	}
}
