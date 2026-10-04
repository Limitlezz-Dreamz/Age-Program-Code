# Fetch external EVTX sample datasets into tests/fixtures/ext/ (gitignored).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = (Resolve-Path "$PSScriptRoot\..").Path }
$Ext = Join-Path $Root "tests\fixtures\ext"
$Pins = Join-Path $Root "tests\fixtures\PINS"
New-Item -ItemType Directory -Force -Path $Ext | Out-Null

function Pin-Repo([string]$Name, [string]$Url, [string]$Commit) {
    $Dest = Join-Path $Ext $Name
    if (Test-Path (Join-Path $Dest ".git")) {
        Write-Host "Updating $Name…"
        git -C $Dest fetch --depth 1 origin $Commit
        git -C $Dest checkout --force $Commit
    } else {
        Write-Host "Cloning $Name @ $Commit…"
        if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
        git clone --filter=blob:none --no-checkout $Url $Dest
        git -C $Dest fetch --depth 1 origin $Commit
        git -C $Dest checkout --force $Commit
    }
    Add-Content -Path "$Pins.tmp" -Value "$Name $Commit"
}

Remove-Item -ErrorAction SilentlyContinue "$Pins.tmp"
New-Item -ItemType File -Force -Path "$Pins.tmp" | Out-Null

Pin-Repo "EVTX-ATTACK-SAMPLES" "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git" "master"
Pin-Repo "hayabusa-sample-evtx" "https://github.com/Yamato-Security/hayabusa-sample-evtx.git" "main"
Pin-Repo "EVTX-to-MITRE-Attack" "https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack.git" "master"

Move-Item -Force "$Pins.tmp" $Pins
Write-Host "Fixtures ready under $Ext"
Write-Host "Set LW_FIXTURES=1 to enable ignored fixture tests."
