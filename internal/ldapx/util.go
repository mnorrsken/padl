package ldapx

import (
	"strconv"
	"strings"
)

func lower(s string) string { return strings.ToLower(s) }

func parseUint(s string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// displayDN is how a DN appears inside an error message. The empty DN is the
// root DSE, and printing it as "" would read as a missing value.
func displayDN(dn string) string {
	if strings.TrimSpace(dn) == "" {
		return "(root DSE)"
	}
	return dn
}
