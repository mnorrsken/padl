# Changelog

All notable changes to PADL.

## [0.3.0] - 2026-09-01

### Added
- **Windows installer (MSI)** — a **per-user** package: it installs to
  `%LocalAppData%\Programs\PADL`, adds that to the user's `PATH`, and needs no
  administrator rights, writing nothing outside the user's own profile. CI
  builds it, asserts the package is not per-machine, then installs it, runs the
  binary, checks nothing reached Program Files or the machine `PATH`, uninstalls
  it and checks it left neither behind — on every push.
- **`docs/windows.md`** — how to install, and what to do about "Access is
  denied" on a managed laptop. PADL neither requires nor can request elevation:
  the executable carries no resource section at all, so it has no application
  manifest and therefore no `requestedExecutionLevel`. That message comes from
  application allowlisting, antivirus, or a path rule, and the page gives the
  commands to tell which.

### Known limitations
- Releases are **not code-signed**, which is the usual reason an allowlisting
  policy rejects them. Until that changes, the practical route on a locked-down
  machine is a hash-based allow rule using the published SHA-256.

## [0.2.0] - 2026-09-01

### Added
- **Windows binaries** — releases now carry `windows/amd64` and `windows/arm64`
  alongside linux and darwin, and CI runs the unit tests on a real Windows
  runner. The credential store needs no change: `go-keyring` uses the Windows
  Credential Manager through wincred and maps a missing credential to the same
  `ErrNotFound` that PADL's fall-back-to-prompt path already checks.

### Changed
- **Config location on Windows** is `%AppData%\padl` rather than `~/.config`.
  `$XDG_CONFIG_HOME` still wins on every platform, so a dotfiles setup keeps
  working under WSL and Git Bash. Nothing changes on macOS or Linux.
- **A password the keychain refuses as too large** now says so instead of
  claiming the keychain is unavailable. Windows caps a credential blob at 2560
  bytes.

## [0.1.0] - 2026-08-31

First release. PADL is a terminal LDAP browser: directory tree on the left,
entry attributes on the right, keyboard-driven, one static binary.

### Added
- **Directory browser** — a lazy-loading tree pane and an attribute pane. Every
  directory call runs off the draw thread, so a slow server never freezes the
  terminal and `esc` abandons whatever is in flight.
- **LDAP, StartTLS and LDAPS** — with trust-on-first-use certificate pinning.
  The system trust store is tried first, hostname included; when that fails you
  get the subject, issuer, SANs, validity window and SHA-256 fingerprint, and
  accepting pins that exact certificate for the profile. A server that later
  presents a different certificate raises a distinctly louder prompt naming both
  fingerprints. Nothing is trusted silently, and the "trust" button never has
  focus.
- **Server profiles** — stored at `$XDG_CONFIG_HOME/padl/profiles.yaml` (0600)
  and edited in the app. Bind passwords never reach that file: they go to the OS
  keychain, come from `PADL_PASSWORD_<ID>`, or are typed on each connect. A
  keychain that cannot be reached degrades to a prompt with the reason shown.
- **Followable DNs** — `enter` on an attribute value holding a DN jumps the tree
  to that entry, opening whatever is closed on the way. A value counts as a link
  only if it parses as a DN *and* sits inside a naming context the tree is
  showing, so ordinary text that happens to contain an `=` never becomes a dead
  link. Unreachable targets say why: outside the shown contexts, absent under
  its parent, or beyond a truncated container's child limit.
- **Attribute rendering** — `objectGUID` and `objectSid` as GUIDs and SIDs,
  `userAccountControl` decoded to flag names, generalizedTime and Windows
  FILETIME in local time, and a hex dump on demand for anything binary.
  Operational attributes are fetched only when asked for, and shown dimmed.
- **Server compatibility** — Active Directory, eDirectory, OpenLDAP and lldap
  are recognised from the root DSE. AD's domain partition is surfaced first with
  its Configuration and Schema partitions behind a toggle. Servers that answer a
  one-level search with entries from deeper down — lldap does this at the tree
  root — no longer produce a flat, wrong tree: the real containers are recovered
  from the DNs the server itself returned. A base-scope read that comes back
  with a different entry is reported rather than shown under the requested DN.
  LDAP diagnostic text is passed through with the password scrubbed out, because
  on some servers it is the only thing that says what went wrong.

### Known limitations
- Read-only. Editing, search and LDIF export are the next milestones.
- Containers larger than the profile's child limit (500 by default) are
  truncated with a marker; paged results arrive with the search work.
- Referrals are skipped rather than followed.
- SASL binds (EXTERNAL, GSSAPI) are not implemented; simple and anonymous only.
- The Active Directory and eDirectory code paths are written against the specs
  but have not been run against a real server — see `docs/tested-against.md`.
