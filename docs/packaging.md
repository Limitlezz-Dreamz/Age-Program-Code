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
git tag v0.1.0
git push origin v0.1.0
# or: Actions → Release → Run workflow
```

## Signing

| Platform | Default | Production |
|---|---|---|
| macOS | Ad-hoc (`signingIdentity: "-"`) | Set Apple cert secrets + identity; notarize with Apple ID / team |
| Windows | Unsigned | Configure Authenticode / Tauri signing keys in repo secrets |
| Linux | Unsigned packages | Optional: GPG-sign release assets externally |

Secrets consumed by the workflow when present: `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`.

Without Apple credentials, Apple Silicon builds remain ad-hoc signed so users can still open them after Gatekeeper approval.

## Version sync

Keep these aligned on release:

- workspace `Cargo.toml` → `[workspace.package].version`
- `package.json` → `version`
- `src-tauri/tauri.conf.json` → `version`

`lw_core::APP_VERSION` and Settings → About read the Cargo package version.
