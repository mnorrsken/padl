# PADL

A terminal LDAP browser. Directory tree on the left, entry attributes on the
right, keyboard-driven, one static binary.

```
PADL  Lab  ldaps://ldap.example.com:636  OpenLDAP
╔═══════════════════ Lab ═══════════════════╗┌───────────────── Object ──────────────────┐
║[/] dc=example,dc=com                      ║│dn: uid=jdoe,ou=People,dc=example,dc=com   │
║├──[+] ou=Groups                           ║│                                           │
║└──[+] ou=People                           ║│Attribute    Value                         │
║   ├──[u] uid=asmith                       ║│objectClass  inetOrgPerson                 │
║   └──[u] uid=jdoe                         ║│cn           John Doe                      │
║                                           ║│mail         jdoe@example.com              │
║                                           ║│             john.doe@example.com          │
║                                           ║│memberOf     cn=engineers,ou=Groups,dc=exa │
║                                           ║│             mple,dc=com (enter to follow) │
║                                           ║│title        Systems Engineer              │
╚═══════════════════════════════════════════╝└───────────────────────────────────────────┘

 [tree] enter expand · r reload · y copy dn · a all contexts · tab pane · p servers · q quit
```

## What it does today

- Browse any LDAPv3 directory: lazy tree, attribute view, operational attributes on demand.
- LDAP, StartTLS and LDAPS, with **trust on first use** for certificates that do
  not chain to a system root.
- Server profiles, with bind passwords in the OS keychain rather than a config file.
- **Attributes decoded rather than dumped**, across Active Directory, Exchange,
  eDirectory and Identity Manager: GUIDs and SIDs unpacked, flag words named
  (`userAccountControl`, `groupType`, `systemFlags`, Kerberos encryption types),
  enumerations named (`sAMAccountType`, Exchange recipient types, forest and
  domain functional levels), timestamps in local time, password-policy intervals
  as durations, `proxyAddresses` labelled primary or alias, and
  `DirXML-Associations` and `DirXML-PasswordSyncStatus` unpacked into their
  fields. Everything else is a hex dump on demand, and a value PADL cannot make
  sense of is shown as it arrived rather than guessed at.
- **Followable DNs**: press enter on a `member`, `memberOf`, `manager` — any value
  holding a DN, shown underlined — and you land on that entry's attributes, with
  the tree opening whatever is closed on the way and paging into large containers
  to find it. A value PADL renders rather than shows verbatim is never a link,
  however much of a DN it ends in; enter opens its details instead.
- **Back and forward** through the entries you have visited, like a browser.
- **Search**: type bare words for a quick search — `mar nor` finds entries where
  something starts with `mar` *and* something starts with `nor`, across the
  attributes that server actually supports — or start with `(` to write the LDAP
  filter yourself. Based wherever you are standing, with a scope toggle and this
  session's history.
- **Paged results** (RFC 2696): big containers and big result sets load a page at
  a time instead of stopping at a limit.
- **Bookmarks**, **go to a DN**, **copy an entry as LDIF**, and **export a
  subtree to an LDIF file**.

Still read-only: editing is the next milestone.

## Install

```sh
go install github.com/mnorrsken/padl/cmd/padl@latest
```

Or download from the
[releases page](https://github.com/mnorrsken/padl/releases) — linux, macOS and
Windows, on amd64 and arm64. On Windows use the `.msi`: it installs to
`%LocalAppData%\Programs\PADL`, adds itself to your PATH, and needs no
administrator rights. See [docs/windows.md](docs/windows.md), which also covers
what to do about "Access is denied" on a managed laptop.

Or from a checkout:

```sh
make build      # ./bin/padl
```

## Getting started

Run `padl`, press `p` to open the server list, then `a` to add a server.

| Field | Notes |
| --- | --- |
| ID | Keys the keychain entry and the pinned certificate. It cannot be changed later. |
| Security | `ldaps` (port 636), `starttls` (389), or `none` for plain LDAP. |
| Bind | `simple` with a bind DN, or `anonymous`. Active Directory normally refuses anonymous. |
| Bind DN | Usually a full DN — `cn=admin,dc=example,dc=com`, or `uid=admin,ou=people,dc=example,dc=com` on lldap. Active Directory also takes `admin@example.com` or `EXAMPLE\admin`. It is sent as typed; the server decides. |
| Password from | `keyring`, `prompt`, or `env`. |
| Base DN | Leave empty to use the server's naming contexts. Set it when the server publishes none. |

## Keys

| | |
| --- | --- |
| `tab` / `shift-tab` | move between the tree and the object pane |
| `↑` `↓` / `j` `k` | move |
| `→` `l` `enter` | expand (loads children on first open) |
| `←` `h` | collapse, or step up to the parent |
| `r` | reload the selected node from the server |
| `y` | copy the DN, or the selected value |
| `a` | show or hide the hidden naming contexts |
| `o` | show or hide operational attributes (object pane) |
| `enter` | follow a DN to that entry in the tree, or inspect the value in full (object pane) |
| `/` | search below the selected entry |
| `ctrl-s` | cycle the search scope (in the filter bar) |
| `g` | go to a DN you type in |
| `alt-←` / `<` | back to the previously visited entry |
| `alt-→` / `>` | forward again |
| `b` / `B` | bookmark the selection / open the bookmark list |
| `L` | copy the entry as LDIF |
| `E` | export the entry and everything under it to a file |
| `p` | servers |
| `c` | connect / disconnect |
| `esc` | cancel whatever is loading, or close a dialog |
| `?` / `q` | help / quit |

Copying uses the terminal's OSC 52 clipboard, so it also works over ssh — in
terminals that support it. On Windows use Windows Terminal; the legacy console
host does not support OSC 52.

## Certificates

PADL verifies a server certificate against the system trust store first,
hostname included. If that succeeds, nothing is pinned and you see no prompt.

If it fails, PADL shows the subject, issuer, SANs, validity window and SHA-256
fingerprint, and asks. Accepting pins that exact certificate for that profile.
Later connections compare against the pin and go through silently.

If the server then presents a **different** certificate, you get a distinctly
louder prompt naming both fingerprints. Nothing is trusted silently, and the
"trust" button is never the one that has focus.

## Files

```
$XDG_CONFIG_HOME/padl/          # or ~/.config/padl, or %AppData%\padl on Windows
  profiles.yaml                 # servers (0600 on Unix)
  trust.yaml                    # pinned certificates (0600 on Unix)
```

`padl -paths` prints them. On Windows the mode bits do nothing — access is
governed by the ACL the files inherit from `%AppData%`, which is already
restricted to your account. Bind passwords are never written to either file:
they go to the OS keychain (service `padl`, key = profile ID), come from
`PADL_PASSWORD_<ID>`, or are typed on each connect.

A profile looks like this:

```yaml
profiles:
  - id: corp-ad
    name: Corp AD
    host: dc01.corp.example.com
    port: 636
    security: ldaps
    bind: simple
    bindDN: CN=svc,OU=Service,DC=corp,DC=example,DC=com
    passwordRef: keyring
    baseDN: ""
    timeoutSeconds: 15
    pageSize: 500
```

## Servers

PADL targets standards-compliant LDAPv3 and handles a few vendor differences
explicitly. Quick search in particular uses a **per-server attribute list**
rather than one broad set, because a broad set does not work: RFC 4511 says a
filter naming an unknown attribute simply fails to match, and OpenLDAP behaves
that way — but on lldap a substring match on `sn` or `givenName` returns nothing
*and takes the whole OR down with it*, so a generous filter finds nobody on a
server that has the entry. The bar always shows which attributes it will search.


- **Active Directory** — the domain partition is shown first; the Configuration
  and Schema partitions hide behind `a`. Identifiers, flag words, enumerations,
  FILETIME stamps and the negative FILETIME intervals the password policy is
  stored in are all decoded, as are Exchange's recipient types and
  `proxyAddresses`.
- **eDirectory** — publishes an empty `namingContexts` however you bind, which
  is what the profile's base DN override is for, and refuses a simple bind on
  the plain port, so use `ldaps` or `starttls`. `subordinateCount` is read as
  the child-count hint. Its login and password times are decoded, its policy
  intervals — plain second counts, unlike AD's — read as durations, and each
  `ACL` value is unpacked into the rights it grants, over what, to whom. The
  rights bits mean different things depending on whether the entry protects
  `[Entry Rights]` or a named attribute, and PADL reads the right table.
  Verified against 9.3.3; see [docs/manual-tests.md](docs/manual-tests.md).
- **NetIQ Identity Manager** — `DirXML-Associations` is split into the driver,
  the association state and the key the connected system knows the object by,
  and `DirXML-PasswordSyncStatus` into the outcome, when it happened, the
  server's message and the driver it came from — the two values you read first
  when something is not syncing. Written from the documentation and not yet run
  against a live IDM.
- **OpenLDAP** — recognised from its root DSE, which carries no `vendorName`.
- **lldap** — accepts only `uid=<id>,ou=people,<base>` as a bind DN, and answers
  a one-level search at the root with the whole subtree. PADL rebuilds the real
  containers from that and passes the server's own error text through when a
  bind DN is the wrong shape. Quick search there covers `uid cn mail
  displayName` only, for the reason above.

`docs/tested-against.md` records what has actually been run against what.

## Development

```sh
make test       # unit tests, no network
make race       # under the race detector
make lab        # throwaway OpenLDAP (13389 / 13636), lldap (13390)
                # and an Active Directory domain (13392 / 13638)
make it         # integration tests against the lab
make lab-down
```

To browse the lab by hand rather than run tests against it:

```sh
make lab-profiles     # start every lab server, add a profile for each to your config
padl                  # press p, pick one
make lab-profiles-rm  # take the profiles and their keychain entries away again
```

That writes to your real `profiles.yaml` and, like saving a server in the UI,
puts each lab password in the OS keychain. Only profiles whose ID starts with
`lab-` are touched, and `lab-profiles-rm` removes exactly those. Pass `-prompt`
to `go run ./dev/labprofiles` if you would rather be asked for the password than
have it stored.

The AD container is a Samba domain controller — that is how you get a domain
into a container — and it provisions the domain the first time it starts, which
takes the best part of a minute; the other two are up in seconds. It refuses a
simple bind on an unencrypted connection, the way a DC with LDAP signing
required does, so reach it over LDAPS on 13638 or StartTLS on 13392. Its
administrator password is `Padl-Lab-1` rather than the lab's usual one, because
AD enforces complexity on it; the seeded users have `padl-lab`.

Servers that cannot be run from a public image — eDirectory — have manual tests
instead, gated behind environment variables and skipped by default. If you have
an eDirectory image, copy `dev/edir.env.example` to `dev/edir.env` (gitignored)
and fill it in; `make lab-profiles` then brings that up alongside the rest and
adds a profile for it too. See [docs/manual-tests.md](docs/manual-tests.md).

`make lab` is also the quickest way to try the UI:

```sh
make lab
./bin/padl
# p, a — host 127.0.0.1, port 13636, ldaps,
#        bind DN cn=admin,dc=example,dc=com, password padl-lab
```

The lab's certificate is self-signed and issued for the container's hostname,
so connecting to `127.0.0.1` exercises the trust prompt for real.

## Licence

Apache 2.0.
