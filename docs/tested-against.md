# Tested against

Vendor-specific code paths cannot be covered by the local lab, so this is the
record of what has actually been exercised on a real server.

| Server | Version | Transport | Bind | Tested | Notes |
| --- | --- | --- | --- | --- | --- |
| OpenLDAP | 2.4.57 (`osixia/openldap:1.5.0`) | plain, StartTLS, LDAPS | simple, anonymous | 2026-08-31 | The `make lab` directory. Covered by `make it` on every change. Publishes no `vendorName`; recognised from `structuralObjectClass: OpenLDAProotDSE`. |
| lldap | 0.1.1 (`lldap/lldap:stable`) | plain | simple | 2026-08-31 | In the `make lab` set. Three quirks, all handled — see below. |
| Active Directory | — | — | — | not yet | Needs a real DC. Untested: `defaultNamingContext` ordering, partition hiding, `objectGUID`/`objectSid`/FILETIME rendering against live values. |
| eDirectory | OpenText/NetIQ 9.3.3 (CE26.1) | plain (anonymous only), StartTLS, LDAPS | simple, anonymous | 2026-09-02 | Not in `make it` — there is no public image, so CI cannot run it. Covered by the manual tests in `docs/manual-tests.md`. Findings below. |
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

**Substring filters work on only some attributes, and a failure is contagious.**
`(cn=adm*)` matches, `(uid=adm*)` matches, but `(sn=adm*)` matches nothing — and
`(|(cn=adm*)(sn=adm*))` matches nothing either, so one unsupported attribute
takes the whole OR with it. Equality is fine: `(|(cn=adm*)(sn=Administrator))`
matches. `(objectClass=adm*)` is refused outright with result 53, *"Unsupported
user attribute for substring filter"*. This is why quick-search attribute lists
are per-vendor: lldap gets `uid cn mail displayName`, and the integration tests
pin the quirk so a fix in lldap gets noticed.

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

## eDirectory

Everything PADL does for eDirectory was written from the documentation and left
unproven until 9.3.3 was available to test against. All of it holds, with one
correction.

**`namingContexts` is empty — always.** The code used to say this happened for
anonymous binds; in fact an authenticated administrator sees an empty
`namingContexts` too. So the tree has no roots to discover and the profile's
base DN override is not a nicety, it is required. Without it PADL says so and
names the key that opens the profile editor.

**A simple bind on the plain port is refused** with result 13, *Confidentiality
Required* — the default is `LDAP TLS Required: Yes`. Anonymous reads over plain
LDAP do work. Both StartTLS and LDAPS are available, and the server's
certificate is self-signed, so a first connect goes through the trust prompt.

**`subordinateCount` is the child hint**, as assumed — not `hasSubordinates` and
not `numSubordinates`. `o=padl` reported `subordinateCount: 10` and listed ten
children.

**The eDirectory quick-search attribute list works.** Unlike lldap, eDirectory
tolerates attributes it does not know inside an OR, so the broad list including
`fullName` matches the same entries as `(cn=…)` alone rather than poisoning the
filter.

**RFC 2696 paging is supported** (`1.2.840.113556.1.4.319` is advertised): ten
entries over five pages of two, each seen exactly once.

Other details worth knowing: `subschemaSubentry` is `cn=schema`, not OpenLDAP's
`cn=Subschema`; `ndsconfig` wants the administrator in dotted form
(`cn=admin.o=example`) while LDAP wants commas; and object classes come back
capitalised (`Organization`, `Top`), which PADL already folds.

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
- RFC 2696 paging: a page size of one walks a container to the end, seeing every
  entry exactly once and finishing with an empty cookie
- search by filter, including a malformed filter being reported rather than
  silently matching nothing
- quick search: one word reaching an entry by uid, surname, given name or mail;
  two words narrowing rather than widening; a miss returning nothing
- an LDIF export of a real subtree: version header, one record per entry, values
  intact, no line over 76 columns

Against lldap:

- bind with the one DN shape it accepts, and the two rejections above
- the tree recovering `ou=people` and `ou=groups` from a flattened result
- the root reporting an unreadable entry instead of showing the wrong one
- the wrong-bind-DN dialog carrying the server's own explanation
- the no-paging fallback: lldap advertises no controls at all, so results are
  capped and reported as truncated rather than handed a cookie that would never
  work

## Platforms

| Platform | Built | Tests run | Notes |
| --- | --- | --- | --- |
| macOS (arm64) | yes | full suite, plus integration against the lab | The development machine. |
| Linux (amd64) | yes | full suite in CI, including integration | CI runs on ubuntu-latest. |
| Windows | yes, plus an MSI | unit tests on `windows-latest` in CI; the MSI is built, installed, run and uninstalled there | No lab containers there, so nothing exercises a live server on Windows. Nobody has run the TUI on Windows by hand — see below and `docs/windows.md`. |

### What is unproven on Windows

The unit tests cover the config store, the LDAP layer and the whole UI against a
simulated terminal, and those run on a real Windows runner. What that does *not*
prove:

- **Rendering in a real console.** Use Windows Terminal. The legacy console host
  has no OSC 52, so `y` will not reach the clipboard, and box drawing there is
  historically unreliable.
- **The credential store.** `go-keyring` uses wincred, and it maps a missing
  credential to `ErrNotFound`, which is what PADL's fall-back-to-prompt path
  checks — but the tests use a fake keychain, so no test touches the real
  Credential Manager. A credential blob is capped at 2560 bytes there.
- **File protection.** `Chmod(0600)` only moves the read-only flag on Windows.
  `profiles.yaml` and `trust.yaml` are protected by the ACL they inherit from
  `%AppData%`, not by anything PADL does.
- **Signing.** Nothing PADL ships is code-signed, which is the usual reason an
  application-allowlisting policy refuses it on a managed machine.

What the MSI *has* been proven to do, on every push: install per-user without
writing to Program Files or the machine PATH, put a working `padl.exe` on the
user PATH, and uninstall leaving neither behind.

## Adding a row

When you point PADL at a new server, note the version, what worked, and anything
that needed a vendor branch in `internal/ldapx/vendor.go`.
