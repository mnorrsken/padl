# Manual tests

Some directory servers cannot be brought up from a public image, so CI has
nothing to run against them. The tests for those are gated behind environment
variables and run by hand.

They are ordinary Go tests living next to the code, and they skip silently
unless their variable is set — so `go test ./...` and `make it` are unaffected.

Nothing here hardcodes a server, an image or a registry. Supply your own.

## eDirectory

Verified against OpenText/NetIQ eDirectory 9.3.3 (CE26.1). What the tests found
is written up in [tested-against.md](tested-against.md#edirectory).

### Point them at a server

```sh
export PADL_EDIR=1
export PADL_EDIR_HOST=127.0.0.1          # optional, defaults to 127.0.0.1
export PADL_EDIR_LDAP_PORT=389           # optional
export PADL_EDIR_LDAPS_PORT=636          # optional
export PADL_EDIR_BIND_DN='cn=admin,o=example'
export PADL_EDIR_PASSWORD='...'
export PADL_EDIR_BASE_DN='o=example'

go test ./internal/ldapx/ -run EDir -v
go test ./internal/ui/ -run EDir -v
```

The bind DN is in LDAP form, with commas. (`ndsconfig` itself wants the dotted
form, `cn=admin.o=example` — a long-standing eDirectory trap.)

`PADL_EDIR_BASE_DN` is not optional, and that is the point: eDirectory publishes
an empty `namingContexts`, so PADL cannot discover where the tree starts.

### Bringing up a server

If you have an eDirectory container image, it configures a tree from the
arguments you pass it:

```sh
docker run -d --name padl-edir \
  -p 13391:389 -p 13637:636 \
  <your-edirectory-image> \
  new -t PADLTREE -n o=padl -S edir1 \
      -a cn=admin.o=padl -w '<password>' \
      -i -B 127.0.0.1@524 -L 389 -l 636 --configure-eba-now no
```

Then wait for it — first configuration takes a few minutes, longer under
emulation if the image is amd64 and you are not:

```sh
docker logs -f padl-edir     # wait for "successfully configured"
```

Two things that will waste your time otherwise:

- **`-a` takes the dotted form.** `cn=admin,o=padl` fails with `illegal ds name`.
- **`-i` skips the duplicate-tree lookup.** Without it the configure step hunts
  the network for an existing tree of the same name and can fail.

### What the tests cover

| Test | What it pins down |
| --- | --- |
| `TestEDirVendorDetection` | `vendorName`/`vendorVersion` identify eDirectory, and `dsaName` arrives |
| `TestEDirPublishesNoNamingContexts` | the tree has no discoverable roots, so the base DN override is required |
| `TestEDirRefusesSimpleBindWithoutTLS` | a cleartext simple bind is refused with result 13, reported legibly and without the password |
| `TestEDirStartTLSAndLDAPS` | both upgrade paths work, and the self-signed certificate goes through the trust prompt |
| `TestEDirUsesSubordinateCount` | `subordinateCount` is the child hint, not `hasSubordinates` |
| `TestEDirQuickSearch` | the eDirectory attribute list matches, and does not poison the OR the way lldap's does |
| `TestEDirPaging` | RFC 2696 paging walks a container, seeing each entry once |
| `TestEDirWithoutABaseDNSaysWhatToDo` | with no override, PADL explains rather than showing an empty pane |
| `TestEDirBrowseWithABaseDN` | the tree roots at the override, opens, and loads entries |
| `TestEDirPlainBindIsReportedLegibly` | the connect dialog carries the server's own explanation |
| `TestEDirQuickSearchThroughTheUI` | the search bar offers eDirectory's attributes and the search runs |

Several tests `t.Skip` or `t.Log` rather than fail when a server behaves better
than expected — a build that permits cleartext binds, or one that does publish
`namingContexts`. They are pinning down quirks, and a quirk that has gone away
is not a regression.

## Adding another server

Same shape: gate on `PADL_<VENDOR>=1`, take host, port and credentials from
`PADL_<VENDOR>_*`, name the file `<vendor>_manual_test.go`, and add a row to
[tested-against.md](tested-against.md). Do not commit an image name, a registry
or a credential.
