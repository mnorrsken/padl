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
- Binary attributes rendered rather than dumped: `objectGUID` and `objectSid` as
  GUIDs and SIDs, `userAccountControl` decoded to flag names, timestamps in local
  time, everything else as a hex dump on demand.
- **Followable DNs**: press enter on a `member`, `memberOf`, `manager` — any value
  holding a DN — and the tree jumps to that entry, opening whatever is closed on
  the way.

Editing, search and LDIF export are the next milestones.

## Install

```sh
go install github.com/mnorrsken/padl/cmd/padl@latest
```

Or download a binary for your platform from the
[releases page](https://github.com/mnorrsken/padl/releases) — linux, macOS and
Windows, on amd64 and arm64.

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
| Bind DN | A full DN, not a username: `cn=admin,dc=example,dc=com`, or `uid=admin,ou=people,dc=example,dc=com` on lldap. |
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
explicitly:

- **Active Directory** — the domain partition is shown first; the Configuration
  and Schema partitions hide behind `a`. `objectGUID`, `objectSid`,
  `userAccountControl` and FILETIME attributes are decoded.
- **eDirectory** — `namingContexts` can come back empty for an anonymous bind,
  which is what the profile's base DN override is for. `subordinateCount` is
  read as the child-count hint.
- **OpenLDAP** — recognised from its root DSE, which carries no `vendorName`.
- **lldap** — accepts only `uid=<id>,ou=people,<base>` as a bind DN, and answers
  a one-level search at the root with the whole subtree. PADL rebuilds the real
  containers from that and passes the server's own error text through when a
  bind DN is the wrong shape.

`docs/tested-against.md` records what has actually been run against what.

## Development

```sh
make test       # unit tests, no network
make race       # under the race detector
make lab        # throwaway OpenLDAP (13389 / 13636) and lldap (13390)
make it         # integration tests against the lab
make lab-down
```

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
