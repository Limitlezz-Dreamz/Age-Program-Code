# Packaging and releases

Logwarden ships as a Tauri 2 desktop app plus a headless `lw` CLI.

## Local bundle

```bash
npm ci
just bundle          # npm run tauri build → platform installers under src-tauri/target/.../bundle
```

Requires platform webview tooling (WebView2 / WKWebView / webkit2gtk). Linux deps match CI:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf xdg-utils
```

## Bundled resources

`src-tauri/tauri.conf.json` embeds:

- `resources/mappings`
- `resources/builtin-rules`
- `resources/mitre`
- `resources/event-descriptions.yml`

At startup the GUI installs process-wide paths (also overridable via env for CLI):

| Mechanism | Purpose |
|---|---|
| `install_resource_root` / `LOGWARDEN_RESOURCES` | Directory containing `builtin-rules/`, `mappings/`, … |
| `install_data_dir` / `LOGWARDEN_DATA_DIR` | Writable settings, recent cases, installed Sigma packs |

CLI / tests resolve the same layout via CWD or `CARGO_MANIFEST_DIR` when overrides are unset.

## GitHub Release workflow

`.github/workflows/release.yml` runs on `v*` tags and `workflow_dispatch`:

| Runner | Artifacts (typical) |
|---|---|
| macOS Apple Silicon | `.dmg` / `.app` (aarch64) |
| macOS Intel | `.dmg` / `.app` (x86_64) |
| Ubuntu 22.04 | `.deb`, `.AppImage` |
| Windows | NSIS `.exe`, `.msi` |

Draft releases are created as **Logwarden v\_\_VERSION\_\_** (version from `tauri.conf.json`).

### Trigger

```bash
git tag v0.1.1
git push origin v0.1.1
# or: Actions → Release → Run workflow
```

## Code signing (optional secrets)

Add secrets under **Repo → Settings → Secrets and variables → Actions**. The workflow only injects cert env vars when the secret is non-empty (empty `APPLE_*` breaks ad-hoc macOS builds).

| Secret | Purpose |
|---|---|
| `APPLE_CERTIFICATE` | Base64 `.p12` for Developer ID Application |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the `.p12` |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: …` (overrides ad-hoc `-`) |
| `APPLE_ID` / `APPLE_PASSWORD` / `APPLE_TEAM_ID` | Notarization |
| `WINDOWS_CERTIFICATE` | Base64 PFX for Authenticode |
| `WINDOWS_CERTIFICATE_PASSWORD` | PFX password |
| `TAURI_SIGNING_PRIVATE_KEY` | Minisign private key for **updater** artifacts |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Optional password for that key |

Without Apple secrets, `signingIdentity: "-"` (ad-hoc) is used. Without Windows secrets, installers are unsigned.

### Updater keys

Public key is embedded in `src-tauri/tauri.conf.json` → `plugins.updater.pubkey`.

Generate a new pair (if rotating):

```bash
npx tauri signer generate -w .tauri/logwarden.key
# commit only the pubkey string into tauri.conf.json
# add private key contents as TAURI_SIGNING_PRIVATE_KEY secret — never commit .tauri/*.key
```

When `TAURI_SIGNING_PRIVATE_KEY` is set, the release workflow enables `createUpdaterArtifacts` and uploads `latest.json` for in-app updates (Settings → Check for updates).

## Version sync

Keep these aligned on release:

- workspace `Cargo.toml` → `[workspace.package].version`
- `package.json` → `version`
- `src-tauri/tauri.conf.json` → `version`

`lw_core::APP_VERSION` and Settings → About read the Cargo package version.
