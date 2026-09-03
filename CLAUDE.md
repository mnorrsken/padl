# PADL

Terminal LDAP browser in Go, built on tview/tcell: directory tree on the left,
entry attributes on the right, keyboard driven, one static binary for linux,
darwin and windows. Used against OpenLDAP, lldap and Active Directory.

## Commands

- `make build` (to `bin/`), `make run`, `make test` (no network), `make race`,
  `make lint`, `make vet`, `make fmt`
- `make lab` / `make lab-down` / `make lab-logs`: throwaway OpenLDAP + lldap +
  an Active Directory domain from `dev/docker-compose.yml`. OpenLDAP is seeded
  from `dev/seed.ldif`, the domain controller by `dev/samba-seed.sh`, and
  `dev/samba-cert.py` issues it a certificate before samba starts the way a real
  DC has one. Samba is the container; AD is what the tests are about, so keep
  test names and comments about AD behaviour rather than Samba's
- `make lab-profiles` / `make lab-profiles-rm`: start every lab server —
  eDirectory included when `dev/edir.env` exists — and add a `lab-*` profile for
  each to the developer's own PADL config and keychain, via
  `dev/labprofiles`. `dev/edir.env` is gitignored and stays that way: there is
  no public eDirectory image, so no image name, registry or credential for it
  belongs in the repo
- `make it`: integration tests against the lab (`PADL_IT=1 go test ./...`)
- `make dist`: the same cross-compile the release does

## Verify before done

`make test` green. `make it` when the change touches binds, searches, paging,
DN handling or the tree loader. Run the TUI once against the lab
(`make lab && make run`) for any UI change; colours, focus and key handling
do not show in tests.

## Layout and conventions

- `internal/ldapx`: all LDAP access (client, entries, attrs, DN, paging,
  quick search, root DSE, TLS). `internal/ui`: tview views (tree, object,
  search, modals, profiles, theme, status). The UI never builds LDAP filters
  itself; it calls `ldapx`.
- Attribute rendering is table-driven: `attr.go` holds the decoders,
  `attr_ad.go` the Active Directory and Exchange tables, `attr_edir.go`
  eDirectory and Identity Manager. Two rules when adding one. A value nobody
  can read (GUID, SID, FILETIME) is *replaced* by its rendering; a value that
  is readable but means more than it says (a flag word, an enumeration, a
  prefixed address) keeps its text and gains the meaning in parentheses, so
  `y` still copies what the directory holds. And a decoder that is not sure
  returns false so the value falls through unchanged — a wrong rendering is
  worse than a raw one.
- `internal/config`: profiles and credential storage. Keychain handling is
  per OS; Windows must not require admin rights.
- `internal/version` is stamped from the git tag at build time. No version
  string in source.
- Quick search splits the query into terms and builds
  `&(|(cn=t*)(sAMAccountName=t)...)` per term; keep that behaviour when
  touching search. Two things are matched as typed rather than by prefix:
  the login identifiers in `exactMatchAttributes` (`uid`, `sAMAccountName`),
  and a single term shorter than `minWildcardTerm`. A wildcard the user typed
  always wins. `ldapx.PrefixSearch` answers which kind of match a query gets,
  so the search bar does not restate the rule.
- `docs/tested-against.md` records what was verified against which directory.
  Update it when you test against a new server. `docs/windows.md` covers the
  Windows install and SmartScreen notes.

## Release notes (what differs from the wiki "GitHub Release Process" skill)

- Changelog heading: `## [X.Y.Z] - YYYY-MM-DD`, no `v`. `release.yml`
  extracts that exact section for the release notes and fails without it.
  `Fixed` means fixed relative to a released version.
- Pre-1.0: breaking changes are a minor bump.
- Release commit: `Add <feature> (vX.Y.Z)`. Tag `vX.Y.Z`, push main and the tag.
- `ci.yml` runs on push/PR; `release.yml` on `v*` tags runs vet, race and the
  integration tests, then cross-compiles, writes `checksums.txt` and creates
  the GitHub release.
