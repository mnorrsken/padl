# Tested against

Vendor-specific code paths cannot be covered by the local lab, so this is the
record of what has actually been exercised on a real server.

| Server | Version | Transport | Bind | Tested | Notes |
| --- | --- | --- | --- | --- | --- |
| OpenLDAP | 2.4.57 (`osixia/openldap:1.5.0`) | plain, StartTLS, LDAPS | simple, anonymous | 2026-08-31 | The `make lab` directory. Covered by `make it` on every change. Publishes no `vendorName`; recognised from `structuralObjectClass: OpenLDAProotDSE`. |
| lldap | 0.1.1 (`lldap/lldap:stable`) | plain | simple | 2026-08-31 | In the `make lab` set. Three quirks, all handled — see below. |
| Active Directory | — | — | — | not yet | Needs a real DC. Untested: `defaultNamingContext` ordering, partition hiding, `objectGUID`/`objectSid`/FILETIME rendering against live values. |
| eDirectory | — | — | — | not yet | Needs a real server. Untested: empty `namingContexts` on anonymous bind, `subordinateCount` as the child hint. |
| 389 Directory Server | — | — | — | not yet | Expected to behave as generic LDAPv3. |

## lldap

lldap is small and opinionated, and it broke three assumptions worth writing down.

**Bind DNs have one legal shape.** Only `uid=<id>,ou=people,<base>` is accepted;
`cn=admin,<base>` is refused with a naming violation (64), and a bare `admin`
with *"Missing DN value"*. The server's diagnostic names the shape it wants, so
PADL keeps LDAP diagnostic text instead of reducing a bind failure to its result
code. A bind DN that is not a DN at all is now caught before dialling.

**Every search ends with an entry-less message.** lldap attaches a control to
`searchResDone`, and go-ldap's `SearchAsync` delivers that as a message where
`Next()` reports true but `Entry()` is nil. PADL used to dereference it, which
was a segfault on the first search — and would have hit any server that returns
controls or referrals on the done message, paged results included.

**One-level search at the root returns the whole subtree.** Asking for the
children of `dc=example,dc=com` yields the users and groups directly, while
`ou=people` and `ou=groups` — which do exist and read correctly — never appear.
PADL now keeps only entries that really are one level down and folds anything
deeper back into the ancestor it belongs under, inferred from the DNs the server
itself returned. On a server with correct scope handling this changes nothing.

A base-scope read at the lldap root has the same problem, returning four
unrelated entries. PADL matches the requested DN among the results and reports
that it could not read the entry rather than showing someone else's attributes
under its heading.

## What the lab does cover

`make it` runs the full stack — real go-ldap, real TLS handshake, real UI on a
simulated terminal — against the throwaway OpenLDAP:

- simple bind, anonymous bind, and a rejected bind that must not leak the password
- root DSE and naming-context discovery, including anonymously
- one-level enumeration, truncation, and base-scope attribute reads
- operational attributes only when asked for
- LDAPS and StartTLS trust-on-first-use: prompt, pin, silent reconnect, and a
  mismatched pin reported as a change
- context cancellation actually abandoning a search

Against lldap:

- bind with the one DN shape it accepts, and the two rejections above
- the tree recovering `ou=people` and `ou=groups` from a flattened result
- the root reporting an unreadable entry instead of showing the wrong one
- the wrong-bind-DN dialog carrying the server's own explanation

## Adding a row

When you point PADL at a new server, note the version, what worked, and anything
that needed a vendor branch in `internal/ldapx/vendor.go`.
