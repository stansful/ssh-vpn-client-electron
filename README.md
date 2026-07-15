# Shadow SSH Desktop

Electron + TypeScript desktop client for `shadow-ssh`.

The default app path uses the built-in live SSH service in the Electron main process. It performs real TCP SSH
connection setup, KEX, host-key fingerprint verification, password/private-key auth, keepalive, direct-tcpip checks,
and shell channel terminal IO through the custom SSH core.

An OpenSSH `SHA256:...` server fingerprint can be pinned optionally. Leaving it blank connects immediately after the
SSH key-exchange signature is verified, matching the default connection workflow.

A native service binary also exists for Windows/macOS/Linux x64/arm64 packaging and Windows Service Control Manager
tests. Use `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1` when you explicitly want Electron to start that native service
binary instead of the built-in live SSH service.

## Requirements

- Windows 10/11 for Windows EXE validation.
- PowerShell 5.1+ or PowerShell 7+.
- Node.js 22.12+ or 24+ (matching the Electron 42 build-tool requirement).
- npm 10+.
- Go 1.23+ for production packaging, because native service binaries are rebuilt for Windows/macOS/Linux x64/arm64
  before packaged artifacts are produced.

Run an environment check:

```powershell
.\scripts\check-env.ps1
```

## Install

```powershell
.\scripts\install.ps1
```

or:

```powershell
npm install
```

## Local development

```powershell
.\scripts\dev.ps1
```

or:

```powershell
npm run dev
```

The renderer runs through Vite. Electron loads the local Vite URL in development.

## Local IPC service simulator

The app can exercise the local IPC service boundary over a standalone simulator. Start it in one terminal:

```powershell
.\scripts\service-simulator.ps1
```

Then start the app in another terminal with `SHADOW_SSH_SERVICE_ENDPOINT` set to the printed endpoint.

On Windows the default endpoint is:

```text
\\.\pipe\shadow-ssh-service
```

On macOS/Linux the default endpoint is a Unix socket under `SHADOW_SSH_RUNTIME_DIR`, `XDG_RUNTIME_DIR`, or
`~/.shadow-ssh/run`. If the endpoint is missing or unreachable, Electron falls back to the built-in live SSH service
and adds a startup diagnostic warning.

Set `SHADOW_SSH_SERVICE_TOKEN` in both Electron and the service process to require a shared local command token on the
IPC protocol. The Windows installer pins the named-pipe ACL to the installing user's SID (plus LocalSystem and
administrators). Set `SHADOW_SSH_ALLOWED_CLIENT_SID` before `npm run service:install` only when installation is run
under a different administrator account than the desktop user.

## Build

Production build without packaging:

```powershell
npm run build
```

Production package preparation rebuilds the native service binaries first, then builds Electron renderer/main, then
runs Electron Builder. Platform artifacts are written to `release/`.

Portable/package scripts use prepared Electron runtime folders in `.cache/electron-<platform>-<arch>` when present, so
packaging can run without downloading Electron during the build. If a local runtime folder is missing, the wrapper lets
Electron Builder use its normal download/cache behavior.

Runnable portable artifacts are the default production packaging mode. Windows gets both unpacked folder builds with
`Shadow SSH.exe` inside and single-file portable `.exe` artifacts in `release/`, macOS gets an unpacked `.app` bundle
directory, and Linux gets AppImage. No ZIP, tarball, DMG, DEB, or installer is produced by the default portable
commands.

Windows portable:

```powershell
npm run build:portable-win
```

or:

```powershell
.\scripts\build-portable-win.ps1
```

Windows folder-only portable, which does not self-extract to `%TEMP%`:

```powershell
npm run build:portable-win-dir
```

Windows single-file portable `.exe` only:

```powershell
npm run build:portable-win-exe
```

The single-file Windows portable `.exe` is convenient to copy, but Electron Builder runs it by self-extracting runtime
resources to `%TEMP%`. Use `release/win-unpacked/Shadow SSH.exe` or `release/win-arm64-unpacked/Shadow SSH.exe` when
that behavior is not acceptable.

macOS portable `.app`:

```sh
npm run build:portable-mac
```

or:

```sh
./scripts/build-portable-mac.sh
```

Linux portable AppImage:

```sh
npm run build:portable-linux
```

or:

```sh
./scripts/build-portable-linux.sh
```

All configured portable production targets:

```sh
npm run build:portable
```

This cleans `release/` first, then builds the runnable portable artifacts for every configured platform and
architecture. Target-specific commands such as `build:portable-win` do not clean the whole `release/` directory.

`npm run build:prod` and `npm run build:prod-*` are aliases to the portable build commands, so production builds do not
produce installers by default.

Opt-in installable packages are still available only when explicitly requested:

```sh
npm run build:installer-win
npm run build:package-mac
npm run build:package-linux
```

Producing fully signed/notarized macOS artifacts must be done on macOS, Windows artifact validation should be done on
Windows, and Linux package validation should be done on Linux. Cross-platform native service binaries are still
generated by `npm run native:build-service`.

Release artifact names include platform and architecture, for example:

```text
release/win-unpacked/Shadow SSH.exe
release/win-arm64-unpacked/Shadow SSH.exe
release/shadow-ssh-0.1.0-windows-portable-x64.exe
release/shadow-ssh-0.1.0-windows-portable-arm64.exe
release/mac/Shadow SSH.app
release/mac-arm64/Shadow SSH.app
release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage
release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage
```

If a signing certificate is configured through Electron Builder environment variables such as `CSC_LINK` and
`CSC_KEY_PASSWORD`, production packaging will use it.

The canonical app icon is `icon.svg`; generated package icons live in `resources/icons/`. macOS uses a separate
16x16/32x32 monochrome template image for the menu bar so the system can tint it correctly in light and dark modes.

Development EXE:

```powershell
.\scripts\build-dev-exe.ps1
```

## Test and lint

```powershell
.\scripts\test.ps1
.\scripts\lint.ps1
```

or:

```powershell
npm run test
npm run lint
```

## Clean

```powershell
.\scripts\clean.ps1
```

## Windows service scripts

The repository includes service management scaffolding:

```powershell
.\scripts\install-service.ps1
.\scripts\start-service.ps1
.\scripts\stop-service.ps1
.\scripts\uninstall-service.ps1
```

`SHADOW_SSH_SERVICE_EXE` may point to a native service executable. Without it, the installer selects
`native\windows\x64\shadow-ssh-service.exe` or `native\windows\arm64\shadow-ssh-service.exe` from the current OS architecture.

Check code signing variables:

```powershell
.\scripts\check-signing-env.ps1
```

## Diagnostics

Diagnostics are available from the main screen under the Diagnostics panel. The expanded/collapsed preference is
persisted. Logs are reset on a new user Connect action and can be copied with Copy logs.

If the initial state cannot be loaded, the startup screen shows the IPC/preload error and a Retry button instead of
remaining on `Loading Shadow SSH...`. On Windows, the startup log is `%APPDATA%\Shadow SSH\logs\main.log`; successful
startup contains `Renderer snapshot IPC handshake completed` and `startupState=ready`.

Diagnostics must not include:

- SSH passwords;
- private keys;
- private key passphrases;
- terminal commands;
- terminal output.

## Client resource and power policy

The client keeps the active SSH/Xray data path independent from its power policy, so battery and thermal state do not
throttle tunnel throughput. Only low-priority UI and process-routing discovery work is reduced:

- a Windows login start in the tray does not create a Chromium renderer until the window is first opened;
- after 30 seconds in the tray, the renderer is released by default to return its Chromium/React memory to the OS;
  the SSH/Xray services keep running in the main process and the window is recreated on demand (unsaved form input is
  discarded; the behavior can be disabled in Settings);
- hidden/minimized renderers receive no streaming terminal or diagnostic IPC and resynchronize from a bounded snapshot
  when shown again;
- process-name routing completes a bounded 1/2/4/8-second discovery burst after connect or rule changes so
  multi-endpoint API/CDN/WebSocket applications are not frozen at their first socket. It enriches public destination
  IPs with exact A/AAAA and reverse-CNAME hostnames from the local Windows DNS cache (without a network lookup).
  A sole public process/IP/hostname tuple immediately adds an exact session route (at most 256) without suppressing
  its working IP and TTL hostname fallbacks; ambiguous/shared destinations retain the same bounded fallbacks (at most
  2,048 IPs and 512 hostnames).
  The compatibility snapshot then refreshes every 10 seconds on AC or battery;
- SSH keepalive and time-based rekey share one deadline timer, while byte-based rekey is checked on active traffic and
  causes no idle polling;
- accepted SSH upload frames are pipelined through a bounded 4 MiB socket buffer instead of waiting for one
  Windows write callback per packet, while a real full buffer still pauses on `drain`;
- loopback proxy sockets use native inactivity deadlines and no redundant TCP keepalive probes;
- terminal history is capped at 2 MiB in the main process and at 1 MiB in the visible DOM; large routing/profile lists
  are rendered in explicit pages; live diagnostics are capped at 1 MiB in aggregate and 64 KiB per message;
- routing lookups and DNS/process caches use bounded indexes instead of repeated full scans, while stalled proxy queues,
  persisted stores, and profile/domain collections have explicit memory and disk safety limits;
- Windows process snapshots still use the compatible full TCP-table query, but serialize only selected-process rows;
  large PowerShell payloads are streamed through stdin, and PAC IP matching performs one extended DNS resolution with
  a legacy fallback instead of resolving every unmatched hostname twice;
- update metadata and binary downloads bypass the renderer/web cache, avoiding duplicate cached copies on disk.

The renderer keeps Electron background throttling enabled, omits unused WebGL, and avoids continuous hidden animation
or backdrop-blur composition. The single-outbound Xray configuration also omits redundant HTTP/TLS/QUIC sniffing.

## Storage

Normal data is stored in Electron `userData` under `storage/app-store.v1.json`.

Secrets are stored separately in `storage/secret-store.v1.json` and encrypted with Electron `safeStorage` when
available. On Windows, Electron `safeStorage` uses OS-backed protection. A local AES-GCM fallback exists only for
development environments where `safeStorage` is unavailable.

The store has a schema version so future migrations can be added without changing UI code.

## Native service and platform targets

Future privileged service binaries are resolved by platform and architecture:

```text
native/windows/x64/shadow-ssh-service.exe
native/windows/arm64/shadow-ssh-service.exe
native/macos/x64/shadow-ssh-service
native/macos/arm64/shadow-ssh-service
native/linux/x64/shadow-ssh-service
native/linux/arm64/shadow-ssh-service
```

The resolver is in:

```text
src/main/platform/targets.ts
```

The Electron main process talks to a service abstraction. Resolution order:

1. `SHADOW_SSH_SERVICE_ENDPOINT`: connect to an already running local IPC service.
2. `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1`: start the packaged native binary over stdio.
3. Default: use the built-in live SSH service in Electron main.

The native binary supports `--stdio`, local endpoint mode, and Windows `--service` mode. Windows service install script
uses:

```text
shadow-ssh-service.exe --service --endpoint "\\.\pipe\shadow-ssh-service"
```

## Routing

Routing modes:

- Proxy all.
- Selected rules.

Selected rules requires at least one enabled domain, IP/CIDR, or process name rule. The UI and main process both block
Connect without enabled rules.

The default live SSH service starts a local HTTP/SOCKS listener after SSH auth succeeds. Traffic accepted by that
listener is forwarded through SSH `direct-tcpip` channels.

The Windows system-proxy/PAC path cannot attach a private credential to each loopback proxy request, so the ephemeral
HTTP/SOCKS listener is loopback-only but unauthenticated. On a shared/RDP host, another local OS user may be able to
discover and use that port; use this portable backend only with trusted local accounts. Strict per-user isolation
requires a privileged WFP dataplane, which is not bundled here.

On Windows, the app applies user-level system proxy settings while connected and restores the previous settings on
Disconnect/app quit:

- Proxy all: sets Windows HTTP/HTTPS/SOCKS proxy entries pointing at the local HTTP/SOCKS listener.
- Selected domain/IP rules: writes a PAC file under the app data directory, serves it through a loopback HTTP PAC
  endpoint, and sets `AutoConfigURL` for enabled domain, exact IP, and IPv4 CIDR rules. The PAC resolves hostnames
  before CIDR checks so IP rules can match destinations reached by domain name.
- Process-name rules: Windows PAC/system proxy has no process context, so the portable backend watches Windows TCP
  connections for enabled process names, adds matched public remote IPs as temporary rules, and converts local DNS-cache
  matches into exact-domain rules. An unambiguous tuple is retained for the connected session while its immediately
  working IP and TTL-domain fallbacks remain active, so short-lived sockets cannot leave the PAC without a route.
  Shared IPs, multiple aliases, private/special-use addresses, and direct-list conflicts stay on conservative bounded
  fallbacks.
  Reviewed bootstrap host families are included for applications such as Discord whose critical API/CDN/WebSocket
  sockets otherwise disappear behind the loopback proxy. Other destinations remain `DIRECT`; already-open target
  sockets may need reconnect, and strict per-process enforcement still requires WFP/TUN.

This process mode is best-effort TCP/system-proxy routing: PAC destination rules are global once learned, and an
application may place network sockets in a helper executable with a different name. Raw sockets, custom proxy/DNS
stacks, QUIC, and clients that ignore the Windows user proxy can bypass this path; add the network-owning helper name
or explicit domain rules when needed.

UDP is production TCP-only: unsupported UDP traffic is not proxied. This means application UI/API/WebSocket traffic
can use process routing, while UDP-only voice/video paths (including Discord voice) remain outside the SSH tunnel.

Kernel-level WFP/TUN packet redirection is not bundled. The supported production interception path in this repository
is TCP over HTTP/SOCKS system proxy/PAC plus live SSH `direct-tcpip`; process-name selected rules use the dynamic
process destination PAC behavior described above.

Live SSH orchestration in the Electron main service path includes KEX, NEWKEYS, encrypted packets, host-key fingerprint
verification, password/private-key auth, keepalive, reconnect, direct-tcpip checks, HTTP/SOCKS direct-tcpip forwarding, and
shell channel IO.

## Project layout

```text
src/core/        Own routing matcher, SSH protocol primitives, and local proxy helpers.
src/shared/      Shared types, defaults, IPC contracts, validation.
src/main/        Electron main process, storage, process listing, platform resolver.
src/preload/     Context-isolated bridge exposed to the renderer.
src/service/     Service abstractions, live SSH service, native process client, and simulator.
src/service/service-host.ts  Standalone local IPC simulator host.
src/renderer/    React UI screens.
native/          Future privileged service binaries by OS and architecture.
scripts/         PowerShell and POSIX workflow scripts.
tests/           Focused validation tests.
```
