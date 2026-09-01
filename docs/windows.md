# PADL on Windows

## Install

Run the `.msi` from the [releases page](https://github.com/mnorrsken/padl/releases).
It installs to `%LocalAppData%\Programs\PADL`, adds that to your user `PATH`,
and **needs no administrator rights** — it writes nothing outside your own
profile and touches no machine-wide setting.

The bare `.exe` works too; put it wherever you like.

Use **Windows Terminal**, not the legacy console host. PADL draws a box-drawing
UI and copies with OSC 52; the old console supports neither well.

## "Access is denied" when running padl.exe

**PADL does not require administrator rights, and cannot ask for them.** The
executable has no resource section at all — no application manifest, so no
`requestedExecutionLevel`. A 64-bit binary without a manifest runs as
`asInvoker` by definition, and UAC's installer-detection heuristics only apply
to unmanifested 32-bit binaries.

To check it yourself, Sysinternals `sigcheck` prints an executable's manifest —
for PADL it prints none, because there is none:

```powershell
sigcheck -m .\padl.exe
```

So "Access is denied" is coming from the machine's policy, not from PADL. On a
managed work laptop it is almost always one of these, in rough order of
likelihood:

### 1. Application allowlisting (AppLocker or WDAC)

The usual cause, and the one that produces exactly "Access is denied". Many
organisations only permit signed executables, or block execution from
user-writable paths like `Downloads`.

```powershell
# Did AppLocker block it? Look for EventID 8004 (exe blocked).
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 20 |
  Where-Object { $_.Message -like '*padl*' } | Format-List TimeCreated, Id, Message

# What rules are in force?
Get-AppLockerPolicy -Effective -Xml
```

If this is it, no change to PADL fixes it — the binary needs to be signed by a
publisher your organisation trusts, or your IT team needs to allow it by hash.
Give them the SHA-256 from the release's `checksums.txt`; a hash rule is the
easiest thing for them to grant.

### 2. Antivirus or EDR quarantine

A new, unsigned Go binary downloaded from the internet is a common false
positive.

```powershell
Get-MpThreatDetection | Select-Object -First 5 InitialDetectionTime, Resources
```

### 3. Mark-of-the-Web

Files downloaded from the internet carry a "blocked" marker. This usually
produces a SmartScreen prompt rather than "Access is denied", but it costs
nothing to clear:

```powershell
Unblock-File .\padl.exe
```

### 4. Execution blocked from that folder

Try somewhere else — a path-based rule may allow `%LocalAppData%\Programs` while
blocking `Downloads`. This is one reason the MSI installs where it does:

```powershell
# Or just run the .msi, which puts it here for you.
mkdir "$env:LOCALAPPDATA\Programs\PADL"
Copy-Item .\padl.exe "$env:LOCALAPPDATA\Programs\PADL\"
& "$env:LOCALAPPDATA\Programs\PADL\padl.exe" -version
```

### 5. Wrong architecture

An arm64 binary on an x64 machine fails, though with "not a valid Win32
application" rather than "Access is denied".

```powershell
$env:PROCESSOR_ARCHITECTURE   # AMD64 or ARM64
```

## Code signing

PADL's releases are **not signed**. That is the single thing most likely to make
an allowlisting policy reject them, and it cannot be fixed from the code — it
needs a code-signing certificate from a CA the organisation trusts.

If you have one, the release workflow has a place to slot it in; without one,
the practical route on a managed machine is to ask IT for a hash-based allow
rule using the published SHA-256.

## Where PADL keeps its files

```
%AppData%\padl\profiles.yaml     servers
%AppData%\padl\trust.yaml        pinned certificates
```

`padl -paths` prints them. Set `XDG_CONFIG_HOME` to override — useful if you
share a config with WSL.

Bind passwords are not in those files. They go to the **Windows Credential
Manager** under the target `padl`, via the same code path as macOS Keychain and
libsecret; a credential blob there is capped at 2560 bytes. To see or clear one:

```powershell
cmdkey /list | Select-String padl
```

## What has actually been tested

The unit tests — config store, LDAP layer, and the whole UI against a simulated
terminal — run on `windows-latest` in CI on every push, and the MSI is built,
installed, run, and uninstalled there too. What has *not* been done: nobody has
driven the TUI in a real Windows console, and no test touches the real
Credential Manager. See `docs/tested-against.md`.
