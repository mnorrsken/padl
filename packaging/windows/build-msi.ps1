<#
.SYNOPSIS
  Builds the PADL MSI. Run on Windows with the WiX .NET tool available.

.DESCRIPTION
  Produces a per-user installer: it lands in %LocalAppData%\Programs\PADL and
  adds that to the user's PATH, so installing it needs no administrator rights.

.EXAMPLE
  dotnet tool install --global wix
  .\packaging\windows\build-msi.ps1 -Version 0.2.0 -Arch x64 -ExePath .\padl.exe -OutDir .\dist
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Arch,
  [Parameter(Mandatory = $true)][string]$ExePath,
  [string]$OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'

# An MSI ProductVersion is three numeric fields, so a tag like v0.2.0 has to be
# stripped of its v and of anything after the patch number.
$clean = $Version -replace '^v', ''
if ($clean -notmatch '^\d+\.\d+\.\d+') {
  throw "Version '$Version' is not major.minor.patch; an MSI cannot express it."
}
$msiVersion = $Matches[0]

if (-not (Test-Path $ExePath)) { throw "No executable at $ExePath" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$exeFull = (Resolve-Path $ExePath).Path
$outFile = Join-Path (Resolve-Path $OutDir).Path "padl_${clean}_windows_${Arch}.msi"
$wxs     = Join-Path $PSScriptRoot 'padl.wxs'

Write-Host "Building $outFile (product version $msiVersion, $Arch)"

& wix build $wxs `
  -arch $Arch `
  -define "Version=$msiVersion" `
  -define "ExePath=$exeFull" `
  -out $outFile

if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }
if (-not (Test-Path $outFile)) { throw "wix reported success but produced no file" }

Write-Host "Built $outFile"
