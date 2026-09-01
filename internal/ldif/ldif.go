// Package ldif writes entries in the LDAP Data Interchange Format of RFC 2849.
//
// Writing only: reading LDIF back in belongs with the editing work, and a
// half-implemented parser would be worse than none.
package ldif

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/mnorrsken/padl/internal/ldapx"
)

// LineWidth is where RFC 2849 folds a long line. Continuations start with a
// single space.
const LineWidth = 76

// WriteEntry writes one entry, followed by the blank line that separates
// records.
func WriteEntry(w io.Writer, e *ldapx.Entry) error {
	if err := writeAttr(w, "dn", []byte(e.DN)); err != nil {
		return err
	}
	for _, a := range e.Attributes {
		// Operational attributes are the server's own bookkeeping. Writing them
		// out would produce a record that cannot be fed back in.
		if a.Operational {
			continue
		}
		for _, v := range a.Values {
			if err := writeAttr(w, a.Name, v); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// WriteEntries writes a set of entries as one LDIF document.
func WriteEntries(w io.Writer, entries []ldapx.Entry) error {
	if _, err := io.WriteString(w, "version: 1\n\n"); err != nil {
		return err
	}
	for i := range entries {
		if err := WriteEntry(w, &entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// String renders one entry as LDIF, for the clipboard.
func String(e *ldapx.Entry) string {
	var b strings.Builder
	_ = WriteEntry(&b, e)
	return strings.TrimRight(b.String(), "\n")
}

// writeAttr writes one name/value pair, base64-encoding and folding as needed.
func writeAttr(w io.Writer, name string, value []byte) error {
	line := name + ": " + string(value)
	if needsBase64(value) {
		line = name + ":: " + base64.StdEncoding.EncodeToString(value)
	}
	_, err := io.WriteString(w, fold(line)+"\n")
	return err
}

// needsBase64 reports whether a value has to be encoded rather than written
// literally. RFC 2849 requires it for anything that is not SAFE-STRING: values
// that are not valid UTF-8, contain NUL, LF or CR, start with a space, colon or
// less-than, or end with a space.
func needsBase64(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	if !utf8.Valid(v) {
		return true
	}
	switch v[0] {
	case ' ', ':', '<':
		return true
	}
	if v[len(v)-1] == ' ' {
		return true
	}
	for _, c := range v {
		if c == 0x00 || c == '\n' || c == '\r' {
			return true
		}
		// Anything outside printable ASCII is safest encoded; a bare high byte
		// in a text file is exactly what makes an LDIF unreadable elsewhere.
		if c > 0x7e {
			return true
		}
	}
	return false
}

// fold breaks a long line the way RFC 2849 wants: continuations begin with a
// single space, which the reader strips.
//
// The split is by byte, not rune, because the format is defined in bytes — and
// anything with multi-byte characters has already been base64-encoded by the
// time it gets here.
func fold(line string) string {
	if len(line) <= LineWidth {
		return line
	}
	var b strings.Builder
	b.WriteString(line[:LineWidth])
	for i := LineWidth; i < len(line); i += LineWidth - 1 {
		end := i + LineWidth - 1
		if end > len(line) {
			end = len(line)
		}
		b.WriteString("\n ")
		b.WriteString(line[i:end])
	}
	return b.String()
}

// Comment renders a header comment, which is how an export records where it
// came from.
func Comment(format string, args ...any) string {
	text := fmt.Sprintf(format, args...)
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		b.WriteString("# " + line + "\n")
	}
	return b.String()
}
