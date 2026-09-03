# Changelog

All notable changes to PADL.

## [0.7.0] - 2026-09-03

### Added
- **Attribute decoding across Active Directory, Exchange, eDirectory and NetIQ
  Identity Manager** — about eighty attributes. GUIDs and SIDs unpacked, flag
  words named (`userAccountControl`, `groupType`, `systemFlags`,
  `msDS-SupportedEncryptionTypes`), enumerations named (`sAMAccountType`,
  Exchange recipient types, forest/domain functional levels), FILETIME and
  generalizedTime stamps rendered in local time, the AD password policy's
  negative FILETIME intervals shown as durations, `proxyAddresses` labelled
  primary or alias, eDirectory ACLs unpacked into the rights they grant over
  what to whom, DirXML-Associations split into driver, state and key. A value
  PADL cannot make sense of is shown as it arrived rather than guessed at.
- **An Active Directory domain in `make lab`** — a Samba DC, provisioned and
  seeded — so the AD-specific paths are covered by `make it` for the first
  time. Six integration tests.
- **`make lab-profiles`**: starts every lab server and adds a profile for each
  to your own PADL config and keychain, so the lab can be browsed by hand.
  `make lab-profiles-rm` removes them. eDirectory joins through
  `dev/lab-edir.sh` and a gitignored `dev/edir.env`.

### Changed
- **Quick search matches login identifiers** (`uid`, `sAMAccountName`) as
  typed rather than by prefix — the wildcard added no recall, since the same
  entry's `cn` or `displayName` matches the same prefix, and cost a substring
  scan on the attribute most likely to be indexed for equality. A single
  search term shorter than two characters is also matched as typed: one
  letter by prefix is the whole directory. A wildcard the user typed always
  wins. The search bar says which kind of match is coming.
- **The bind name is sent to the server as typed.** PADL used to require it to
  parse as a DN, which refused the two ways most people log in to Active
  Directory — `administrator@ad.example.com` and `AD\Administrator` — before
  dialling. Only the server knows which names it takes.
- **Following a link lands on the entry's attributes** rather than on the
  tree. Bookmarking (`b`) now works from the object pane too.

### Fixed
- **An LDIF export or clipboard copy could carry an escape sequence out of a
  hostile directory**: control bytes now force the base64 form, and an
  attribute name that is not an AttributeDescription is dropped with a
  comment rather than injecting records into the file.
- **Values PADL renders are no longer mistaken for followable DNs.** An
  eDirectory ACL renders as text ending in the trustee's DN, which parses as
  one and is in the tree — enter now opens the value's details instead of
  walking off to the trustee.
- **The focused pane indicator in the key hints ("[tree]" / "[object]") has
  never been visible**: the hints view had dynamic colours on, so tview read
  it as an unknown colour tag and swallowed it.
- **CI's `GITHUB_TOKEN` no longer inherits the repository default**;
  `ci.yml` declares `contents: read`.

## [0.6.0] - 2026-09-01

### Added
- **Back and forward history** — `alt-←`/`<` and `alt-→`/`>` retrace the entries
  you have visited, the way a browser does. Only deliberate jumps are recorded —
  following a link, choosing a search result, a bookmark, go-to-DN — because
  scrolling a container is reading rather than navigating. A new jump after
  going back drops the forward trail.

### Fixed
- **Starting without a usable terminal crashed instead of explaining.** PADL
  opened the screen itself and handed it to tview, which discards the `Init`
  error, so a failure only surfaced later as a `close of nil channel` panic.
  tview now opens the terminal, and its error is reported: running with no tty
  gives `padl: open terminal: open /dev/tty: no such device or address`,
  `TERM=dumb` gives `terminal not cursor addressable`.
- **Following a link or a search result landed at the naming context** when the
  target was not in the first page of its container. The jump now pages into the
  container looking for it, up to twenty pages. If it still cannot be placed —
  a server with no paged results, say — the entry is loaded into the object pane
  on its own and the status says why, rather than the jump appearing to do
  nothing.
- **Choosing a search result no longer flashes the naming context** on the way,
  which read as the jump having failed.
- **`(enter to follow)` no longer repeats on every value.** A group with two
  hundred members repeated it two hundred times; DN values are underlined
  instead, and what enter does is on the key hints line. The same for
  `(enter to inspect)` on binary values.
- **Back and forward while disconnected** now say so instead of doing nothing.

## [0.5.0] - 2026-09-01

### Added
- **Quick search** — type bare words in the search bar instead of a filter.
  `mar nor` becomes `(&(|(cn=mar*)(sn=mar*)…)(|(cn=nor*)(sn=nor*)…))`: every word
  must match, each against any of the searched attributes, with prefix matching.
  Anything starting with `(` is still sent as a raw LDAP filter, and a wildcard
  you type yourself is kept as written.
- **Per-server search attributes.** The attribute list is chosen from the
  detected vendor rather than being one broad set, and the bar always names the
  attributes it will search. A single generous list is not workable: RFC 4511
  says a filter naming an unknown attribute simply fails to match, and OpenLDAP
  behaves that way, but on lldap a substring match on `sn` or `givenName`
  returns nothing *and takes the whole OR down with it* — so a generous filter
  finds nobody on a server that has the entry. Active Directory gets
  `sAMAccountName` and `userPrincipalName` and deliberately not `uid`, which
  only exists there with the RFC 2307 schema extension; eDirectory gets
  `fullName`; lldap gets the four attributes it can actually substring-match.

## [0.4.0] - 2026-09-01

Milestone 2: search and navigation.

### Added
- **Search** — `/` opens a filter bar taking raw LDAP filter syntax, based at
  whatever the tree has selected so a search is naturally narrowed to where you
  are standing. `Ctrl-S` cycles the scope without losing what you have typed,
  and `↑`/`↓` walk this session's filter history. Results replace the tree on
  the left; moving through them loads each entry on the right, and `enter` takes
  the chosen one back into the tree with its surroundings.
- **Paged results (RFC 2696)** — large containers and large result sets now load
  a page at a time and offer the rest, instead of stopping at a limit. A server
  that does not advertise paging still says plainly that the list was cut short
  and what to do about it, rather than pretending there is more to fetch.
- **Bookmarks** — `b` saves the selected DN on the profile, `B` opens the list,
  and `enter` there goes to the entry, expanding whatever is closed on the way.
- **Go to a DN** — `g` prompts for a DN, for when you have one on the clipboard
  rather than on screen.
- **LDIF** — `L` copies the current entry as RFC 2849 LDIF, and `E` exports the
  selected entry and everything beneath it to a file. Values that are not
  SAFE-STRING are base64-encoded, long lines are folded at 76 columns, and
  operational attributes are left out so the result can be fed back in. An
  existing file is never overwritten.

### Changed
- **Failures that need reading get a dialog**, not just the one-line status bar:
  a rejected search filter and a failed export join connect failures there.

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
