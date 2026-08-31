# PADL release process

## Version scheme
`vMAJOR.MINOR.PATCH` — bump **minor** for new features, **patch** for bug fixes
and small changes. PADL is pre-1.0, so breaking changes go in a minor bump.

## Step-by-step

### 1. Commit the feature/fix changes first
```bash
git add <files>
git commit -m "Short description of change"
```

### 2. Check the current version
```bash
git tag --sort=-v:refname | head -5
```
Latest tag = current version. Pick the next one from the kind of change.

### 3. Update CHANGELOG.md
Add a new section **at the top**, below the intro line and above the previous
version:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- **Feature name** — what it does, from the user's side.

### Changed
- **Thing** — what changed.

### Fixed
- **Bug** — what was wrong and what it means for the user.
```

Only include the headings that apply. `Fixed` means fixed relative to a
*released* version — a bug introduced and fixed between tags does not belong
here; that is what the git history is for.

The release workflow extracts this exact section for the GitHub release notes
and **fails the release if there is no section matching the tag**, so the
heading has to read `## [X.Y.Z]` with no `v`.

### 4. Update README.md if necessary
Only if the change affects documented behaviour, keys, or configuration.

### 5. Update docs/tested-against.md if you ran PADL against a new server
That file is the record of what has actually been verified on which directory
implementation, and against what it has not.

### 6. Commit the changelog (and readme if changed)
```bash
git commit -am "Add <feature> (vX.Y.Z)"
```

### 7. Tag and push
```bash
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

## What happens automatically on a tag push

`.github/workflows/release.yml` triggers on `v*` tags:

1. **test** — `go vet`, `go test -race ./...`, then the integration tests against
   the lab directories in `dev/docker-compose.yml` (OpenLDAP and lldap). Nothing
   is published unless these pass.
2. **release** — cross-compiles `padl` for linux and darwin on amd64 and arm64,
   stamping the tag and commit into `internal/version`, writes `checksums.txt`,
   pulls this version's CHANGELOG section for the notes, and creates the GitHub
   release with the binaries attached.

`.github/workflows/ci.yml` runs the same tests on every push to `main` and every
pull request.

## Local equivalents
```bash
make test       # unit tests, no network
make race       # under the race detector
make lab        # start the throwaway directories
make it         # integration tests against them
make dist       # the same cross-compile the release does
make lab-down
```
