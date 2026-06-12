# Shadow SSH Desktop

Electron + TypeScript desktop client for `shadow-ssh`.

The default app path uses the built-in live SSH service in the Electron main process. It performs real TCP SSH
connection setup, KEX, host-key fingerprint verification, password/private-key auth, keepalive, direct-tcpip checks,
and shell channel terminal IO through the custom SSH core.

A native service binary also exists for Windows/macOS/Linux x64/arm64 packaging and Windows Service Control Manager
tests. Use `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1` when you explicitly want Electron to start that native service
binary instead of the built-in live SSH service.

## Requirements

- Windows 10/11 for Windows EXE validation.
- PowerShell 5.1+ or PowerShell 7+.
- Node.js 20, 22, or 24.
- npm 10+.

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

The app can exercise the future service boundary over local IPC. Start the standalone simulator in one terminal:

```powershell
.\scripts\service-simulator.ps1
```

Then start the app in another terminal with `SHADOW_SSH_SERVICE_ENDPOINT` set to the printed endpoint.

On Windows the default endpoint is:

```text
\\.\pipe\shadow-ssh-service
```

On macOS/Linux the default endpoint is a Unix socket under the OS temp directory. If the endpoint is missing or
unreachable, Electron falls back to the built-in live SSH service and adds a startup diagnostic warning.

Set `SHADOW_SSH_SERVICE_TOKEN` in both Electron and the service process to require a shared local command token on the
IPC protocol. Windows named-pipe ACL hardening still needs validation in the native Windows service.

## Build

Production build without packaging:

```powershell
npm run build
```

Development EXE:

```powershell
.\scripts\build-dev-exe.ps1
```

Production EXE:

```powershell
.\scripts\build-prod-exe.ps1
```

Build artifacts are written to:

```text
release/
```

If a signing certificate is configured through Electron Builder environment variables such as `CSC_LINK` and
`CSC_KEY_PASSWORD`, production packaging will use it.

The canonical app icon is `icon.svg`; generated package icons live in `resources/icons/`.

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

`SHADOW_SSH_SERVICE_EXE` may point to a native service executable. Without it, the scripts expect
`native\windows\x64\shadow-ssh-service.exe`.

Check code signing variables:

```powershell
.\scripts\check-signing-env.ps1
```

## Diagnostics

Diagnostics are available from the main screen under the Diagnostics panel. The expanded/collapsed preference is
persisted. Logs are reset on a new user Connect action and can be copied with Copy logs.

Diagnostics must not include:

- SSH passwords;
- private keys;
- private key passphrases;
- terminal commands;
- terminal output.

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

## Routing and UDP limitations

Routing modes are modeled now:

- Proxy all.
- Selected rules.

Selected rules requires at least one enabled domain, IP/CIDR, or process name rule. The UI and main process both block
Connect without enabled rules.

Current implementation limitations:

- Windows routing driver is still a separate privileged layer and must be validated on Windows;
- no real TUN/WFP packet interception implementation is bundled yet;
- live SSH orchestration exists for the Electron main service path: KEX, NEWKEYS, encrypted packets, host-key fingerprint verification, password/private-key auth, keepalive, direct-tcpip tunnel checks, and shell channel IO;
- local TCP proxy/direct-tcpip byte-pump scaffolding exists and can use live direct-tcpip channels;
- DNS cache and TCP-only UDP policy exist, but OS DNS interception is not implemented yet;
- process-to-connection matching is not implemented yet;
- domain routing does not yet observe DNS traffic;
- UDP support is not implemented and should be designed separately from TCP/DNS.

## Project layout

```text
src/core/        Own routing matcher, SSH protocol primitives, and local proxy helpers.
src/shared/      Shared types, defaults, IPC contracts, validation.
src/main/        Electron main process, storage, process listing, platform resolver.
src/preload/     Context-isolated bridge exposed to the renderer.
src/service/     Service client abstraction and development simulator.
src/service/service-host.ts  Standalone local IPC simulator host.
src/renderer/    React UI screens.
native/          Future privileged service binaries by OS and architecture.
scripts/         Windows-oriented PowerShell workflow scripts.
tests/           Focused validation tests.
```
