# Shadow Desktop: developer notes

Electron + TypeScript desktop client for Shadow (formerly Shadow SSH). The user-facing overview is in the
[README](../README.md); this file covers building, packaging and how the app works inside.

The app is shown as **Shadow**, while its system identity keeps the old name so existing installs keep their data and
saved secrets: the data folder is still `Shadow SSH` (`%APPDATA%\Shadow SSH`, `~/Library/Application Support/Shadow SSH`,
`~/.config/Shadow SSH`), `app.setName("Shadow SSH")` keeps the `Shadow SSH Safe Storage` Keychain/keyring entry, and
the appId, `.deb` package name, Windows TUN adapter, IPC channels, `SHADOW_SSH_*` variables and `shadow-ssh-service`
are unchanged. Release files keep the `shadow-ssh-<version>-…` names that the in-app updater of older versions looks for.

Upgrading from Shadow SSH 2.4.0 or earlier:

- macOS: the DMG now holds `Shadow.app`, so Finder adds it next to `Shadow SSH.app` instead of replacing it. Quit
  Shadow SSH, drag Shadow into Applications, move the old `Shadow SSH` app to the Trash and pin Shadow in the Dock
  again. Servers, keys and saved secrets carry over: both use the same data folder and Keychain entry.
- Windows: run the new portable `.exe` as before; the file names haven't changed.
- Linux: the `.deb` package keeps its name, so `apt` upgrades it in place and moves it from `/opt/Shadow SSH` to
  `/opt/Shadow`. An AppImage is replaced like any other update.

The default app path uses the built-in live SSH service in the Electron main process. It performs real TCP SSH
connection setup, KEX, host-key verification, password/private-key auth, keepalive, direct-tcpip checks,
and shell channel terminal IO through the custom SSH core.

Host and user keys:

- Host-key algorithms, most preferred first: `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`.
- A server's Fingerprint field takes an OpenSSH `SHA256:...` value and wins over everything below. If the key the
  server presents doesn't match and the server also offers another key type the client supports, the client
  reconnects, before authenticating, restricted to the next key type it hasn't tried, until one matches. Otherwise
  the connect fails with a fingerprint mismatch and reconnecting stops. When the expected key's type is known - the
  fingerprint was verified earlier in this run, or the type was saved with the server (`trustedHostKeyType` with a
  trusted key, `pinnedHostKeyType` the first time a pinned fingerprint is verified; it stays as long as the pin does)
  - a non-matching key of that type is final at once: a retry could not match, and a server that drops it must not
  turn the mismatch into a retried network error. While the type is not known yet, a retry that fails for another
  reason stays retryable, and Activity gets a warning naming the key that did not match.
- Without a pinned fingerprint the server is trusted on first use: after the first connect that authenticates, the
  host key's fingerprint is saved with the server (`trustedHostKeyFingerprint`, `trustedHostKeyType`,
  `trustedHostKeyAt`). Every later
  connect and reconnect must present that key. A different key stops with a "host key" error that says to paste
  the new fingerprint into the server's Fingerprint field if the change is expected. Changing the host or port, or
  setting or clearing the pinned fingerprint, forgets the saved key. Within one session the key is required on
  every reconnect even if saving it failed.
- User keys: RSA, Ed25519 and ECDSA, in OpenSSH format (passphrase-protected too) or PEM.

The Go helper `shadow-ssh-service` (`native/service-go`) is a `--stdio` child process that Electron starts on Windows
for process attribution and the TUN dataplane. It carries no SSH traffic: its own `connect` command fails closed
(`sshCoreLinked: false`), so `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1` and `SHADOW_SSH_SERVICE_ENDPOINT` (below) only
exercise the IPC boundary and the Windows Service Control Manager scripts.

## Requirements

- Windows 10/11 for Windows EXE validation.
- PowerShell 5.1+ or PowerShell 7+.
- Node.js 22.12+ or 24+ (matching the Electron 42 build-tool requirement).
- npm 10+.
- Go 1.24.7 or newer for production packaging, because the helper binaries are rebuilt for Windows/macOS/Linux
  x64/arm64 before packaged artifacts are produced. `native/service-go/go.mod` says `go 1.24.1` with
  `toolchain go1.24.7` (an older Go fetches 1.24.7 itself); CI and the committed helper binaries use Go 1.25.

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

The renderer runs through Vite. Electron loads the local Vite URL in development. `npm run dev` runs as "Shadow SSH",
with the same data folder, safe-storage key and single-instance lock as an installed Shadow: quit the installed app
first, or the dev instance exits in its favour. To keep them apart, set `SHADOW_SSH_BUILD_CHANNEL=development` before
`npm run dev`; it then runs as "Shadow SSH Dev" with its own folder, key and lock. Packaged dev builds
(`build:dev-exe`) always run as "Shadow SSH Dev", whatever the environment says.

Separate folders and locks do not make two copies independent once they connect. On Windows both write the same
per-user proxy settings (HKCU Internet Settings), and both name their TUN adapter "Shadow SSH". Do not connect
"Shadow SSH Dev" while the installed Shadow is connected, or the other way round: the copy that connects second
takes the other's proxy for a leftover of its own, and when it disconnects it restores the settings from before
either of them - the first copy then still reads Connected while the traffic its rules select goes direct. Two TUN
helpers also compete for one adapter name and one set of routes. Disconnect one copy before connecting the other.

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

Production package preparation checks the committed Xray binaries against their recorded checksums (see
[Xray runtime](#xray-runtime)), rebuilds the Go helper binaries, then builds Electron renderer/main, then runs
Electron Builder. Platform artifacts are written to `release/`.

Portable/package scripts use prepared Electron runtime folders in `.cache/electron-<platform>-<arch>` when present, so
packaging can run without downloading Electron during the build. If a local runtime folder is missing, the wrapper lets
Electron Builder use its normal download behavior. Auxiliary NSIS, DMG, AppImage, and DEB toolchains are cached in
`.cache/electron-builder` instead of a user-global directory; set `ELECTRON_BUILDER_CACHE` to override that location.

The complete production release is built with:

```sh
npm run build:prod
```

It cleans `release/`, prepares the native services and Electron application once, then builds and verifies the full
two-architecture release matrix:

| Platform | x64 | arm64 |
| --- | --- | --- |
| Windows | portable EXE | portable EXE |
| macOS | DMG | DMG |
| Linux | AppImage, DEB | AppImage, DEB |

The verification step fails the build if any of the 12 production targets is absent or malformed. It also checks the
CPU architecture and bundled `app.asar`, native service, and Xray runtime in each unpacked application. After
verification `release:prune` removes everything except the distributable packages (unpacked folders, builder debug and
config dumps, `latest*.yml` update metadata, and `*.blockmap` files), so `release/` ends up with exactly:

```text
release/shadow-ssh-<version>-windows-portable-x64.exe
release/shadow-ssh-<version>-windows-portable-arm64.exe
release/shadow-ssh-<version>-macos-dmg-x64.dmg
release/shadow-ssh-<version>-macos-dmg-arm64.dmg
release/shadow-ssh-<version>-linux-portable-x86_64.AppImage
release/shadow-ssh-<version>-linux-portable-arm64.AppImage
release/shadow-ssh-<version>-linux-package-amd64.deb
release/shadow-ssh-<version>-linux-package-arm64.deb
```

Complete production builds for one platform are available separately:

```sh
npm run build:prod-win
npm run build:prod-mac
npm run build:prod-linux
```

`build:prod-all` is an alias for the complete build, `build:prod-exe` is an alias for the complete Windows build, and
`build:prod-macos` is an alias for the complete macOS build. Complete production commands clean `release/` first; use
`build:prod` rather than running platform commands one after another when all platforms are required.

Runnable-only portable artifacts remain available when installable packages are not needed. Windows gets unpacked
folder builds with `Shadow.exe` and single-file portable `.exe` files, macOS gets unpacked `.app` bundles, and
Linux gets AppImages.

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
resources to `%TEMP%`. Use `release/win-unpacked/Shadow.exe` or `release/win-arm64-unpacked/Shadow.exe` when
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

Installable packages can also be rebuilt independently without producing the rest of the complete matrix:

```sh
npm run build:installer-win
npm run build:package-mac
npm run build:package-linux
```

Every macOS bundle - signed or not, folder, DMG or portable - must be packed on macOS: the `afterPack` hook re-signs
Electron Framework with `codesign` after flipping its fuses (see [Electron fuses](#electron-fuses)) and stops the build
on any other host. On Linux or Windows, `build:portable-mac`, `build:portable`, `build:portable-all`,
`scripts/build-portable-mac.sh` and `scripts/build-portable-all.sh` therefore fail at the macOS step, before the Linux
one; build the other platforms with their own commands there (`build:portable-win`, `build:portable-linux`). Windows
artifact validation should be done on Windows, and Linux package validation on Linux. Cross-platform native service binaries are still
generated by `npm run native:build-service`.

Portable and opt-in package commands keep all builder output. Artifact names include platform and architecture, for
example:

```text
release/win-unpacked/Shadow.exe
release/win-arm64-unpacked/Shadow.exe
release/shadow-ssh-<version>-windows-portable-x64.exe
release/shadow-ssh-<version>-windows-portable-arm64.exe
release/shadow-ssh-<version>-windows-installer-x64.exe
release/shadow-ssh-<version>-windows-installer-arm64.exe
release/mac/Shadow.app
release/mac-arm64/Shadow.app
release/shadow-ssh-<version>-macos-dmg-x64.dmg
release/shadow-ssh-<version>-macos-dmg-arm64.dmg
release/shadow-ssh-<version>-linux-portable-x86_64.AppImage
release/shadow-ssh-<version>-linux-portable-arm64.AppImage
release/shadow-ssh-<version>-linux-package-amd64.deb
release/shadow-ssh-<version>-linux-package-arm64.deb
```

If a signing certificate is configured through Electron Builder environment variables such as `CSC_LINK` and
`CSC_KEY_PASSWORD`, production packaging will use it.

The canonical app icon is `icon.svg`; generated package icons live in `resources/icons/`. macOS uses a separate
16x16/32x32 monochrome template image for the menu bar so the system can tint it correctly in light and dark modes.

Development EXE:

```powershell
.\scripts\build-dev-exe.ps1
```

### Xray runtime

The Xray binaries are committed under `resources/xray/<platform>/<arch>/` and pinned to Xray-core v26.3.27.
`npm run xray:download` (this machine's platform), `xray:download-win` and `xray:download-all` fetch exactly that
release and refuse an archive or executable whose SHA-256 differs from `scripts/xray-checksums.json`.
`npm run xray:ensure -- --all`, which `package:prepare` runs, checks the committed executables the same way. To move
to a newer release, change `pinnedVersion` in `scripts/download-xray-runtime.mjs`, run
`npm run xray:download-all -- --trust-download`, compare the recorded archive hashes with the `.dgst` files published
with the release, and commit the binaries together with the checksum file.

The `geoip.dat` and `geosite.dat` files next to the binaries are not packaged (the packaging filter ships only
`xray`/`xray.exe`), so the generated Xray config must not use `geoip:` or `geosite:` matchers.

### Electron fuses

Packaged builds flip Electron's fuses (`build.electronFuses` in `package.json`): `ELECTRON_RUN_AS_NODE`,
`NODE_OPTIONS` and the `--inspect` flags are ignored, the app loads only from `app.asar`, and the `app.asar` header is
checked against the hash embedded at packaging time (macOS and Windows; Electron has no such check on Linux). The app
therefore cannot start its own executable as Node: `process.fork` and `ELECTRON_RUN_AS_NODE` don't work in a packaged
build. On macOS the fuse wire lives in Electron Framework, which is re-signed ad hoc after the flip, because an arm64
binary whose signature no longer matches is killed at launch. Read a bundle's fuses with
`npx @electron/fuses read --app release/mac-arm64/Shadow.app`.

electron-builder takes `electronFuses` only at the top level, so every platform gets the same settings. It writes the
`app.asar` hash into `Info.plist` on macOS and into an `INTEGRITY`/`ELECTRONASAR` resource of the exe on Windows, before
it flips the fuses and edits the exe's version and icon (that edit keeps the resource). Portable and NSIS wrap the
same exe. On Linux nothing is embedded and the integrity fuse has no effect.

Only that framework is re-signed (`scripts/mac-fuses.mjs`, from the `afterPack` hook; `resetAdHocDarwinSignature` stays
off). The re-sign needs `codesign`, so the hook refuses to pack a macOS bundle on any other host rather than produce
one that is killed at launch. @electron/fuses' own reset re-signs the whole bundle with `codesign --deep`, which seals `app.asar` and
`Info.plist` into the main executable's signature, so its code hash would change with every release. The macOS builds
aren't signed with a Developer ID, so the "Shadow SSH Safe Storage" Keychain entry's access list names that hash: macOS
would ask for the entry again after every update, and the window doesn't open until the prompt is answered (main waits
in `safeStorage.isEncryptionAvailable()`). Left alone, the main executable keeps Electron's own linker signature, the
same for every release on one Electron version, so an update that keeps the Electron version asks nothing. A new
Electron version still changes it once; only a Developer ID signature removes that. The hook flips the fuses before
electron-builder does; electron-builder's own flip then writes the same bytes, and the framework's signature holds.
Electron ships its x64 macOS build unsigned (only the arm64 linker signs ad hoc), so the x64 framework is flipped and
left unsigned like the rest of that bundle; only the arm64 framework is re-signed. To start a test bundle without touching the real Keychain entry, pass Chromium's `--use-mock-keychain` and point
`SHADOW_SSH_USER_DATA_DIR` at a scratch folder.

## Test and lint

```powershell
.\scripts\test.ps1
.\scripts\lint.ps1
```

or:

```powershell
npm run typecheck
npm run test
npm run lint
npm run native:test-service   # go test ./... in native/service-go
```

Every push to `master` runs the same checks in the Release workflow's `quality` job: typecheck, lint, Vitest,
`go test ./...` and Windows x64/arm64 builds of the helper, with Go 1.25. A release is built only after they pass.
`tests/build-assets.test.ts` also fails when the version in `package-lock.json` differs from `package.json`, so a
release commit bumps both (`npm install --package-lock-only`).

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

The Activity page shows the live event feed, with important events pinned on top until they are dismissed, and the
tail of `main.log`; either can be copied. Settings → Diagnostics turns activity history, live events and the log
file on or off.

If the initial state cannot be loaded, the startup screen shows the IPC/preload error and a Retry button instead of
remaining on `Loading Shadow...`. On Windows, the startup log is `%APPDATA%\Shadow SSH\logs\main.log`; successful
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
  its working IP and hostname fallbacks; ambiguous/shared destinations retain the same bounded fallbacks (at most
  2,048 IPs and 512 hostnames). A learned route cannot be re-observed once it is in the PAC, because the application
  then connects to the loopback proxy instead of the real destination, so every retained route is renewed on each
  successful discovery cycle and only decays after discovery itself has been failing for a full 5-minute TTL.
  The compatibility snapshot then refreshes every 10 seconds on AC or battery;
- SSH keepalive and time-based rekey share one deadline timer, while byte-based rekey is checked on active traffic and
  causes no idle polling; while a session is wanted, one 5-second tick additionally watches for a clock jump and for
  interface changes (see below);
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

## Background connection supervision

The live SSH service treats the connection as a desired state and keeps it there without any server-side support:

- Keepalives are scheduled from the last packet *received* from the server, never from bytes the client sent, so
  applications retrying through a half-open tunnel cannot postpone the probe that would notice it. A keepalive is
  considered answered by any packet from the server (the way OpenSSH counts `ServerAliveCountMax`); only 30 seconds of
  complete silence after a keepalive tears the session down. Sending for 10 seconds without hearing anything back
  (a channel open the server never confirms, data with no window adjust or reply) triggers a 15-second probe at once,
  so a dead socket under traffic is noticed in about 25 seconds regardless of the configured keepalive interval.
- The local HTTP/SOCKS listener outlives the SSH session. When the transport fails the listener keeps its port and
  accepts connections; each waits up to 25 seconds for the new session and then opens its channel there, so a
  WebSocket reconnect, a poll or a page load started during the gap completes instead of failing with "connection
  refused". Connections that were open when the transport died are closed (a TCP stream cannot move to a new SSH
  session), and applications reconnect them through the waiting listener. Only a user Disconnect, a halt or shutdown
  stops the listener.
- System routing (Windows proxy setting, PAC, process discovery, TUN capture) is kept in place while a reconnect is in
  progress. If no session is back after 30 seconds the machine returns to direct routing, exactly as before, and
  routing is re-applied when the session returns. While the TUN adapter is up the reconnect goes to the server
  address the adapter protects, because a fresh lookup could route the transport into its own tunnel; if that address
  does not answer the adapter is released and the next attempt resolves normally.
- The first retry after a failure is immediate; only repeated failures back off (1, 2, 4, 8, 16, 30 seconds with
  jitter). The status goes straight to Reconnecting, without an Error in between.
- The main process forwards `powerMonitor` resume events to the transports, and the service itself watches for a
  clock jump (the process did not run for 15 s or more) and for changes of the machine's non-tunnel interface
  addresses (virtual, VPN and loopback adapters are ignored). Any of these probes a live session with a 15-second
  deadline, and runs a waiting reconnect immediately with the backoff restarted (never closer than one second to the
  previous attempt). A wake that arrives while an attempt is already running is applied to the retry that follows
  it. The backoff is restarted for at most one wake per 30 seconds, so a flapping adapter cannot turn the ladder into
  an attempt every tick.
- Reconnecting stops only for a pinned fingerprint mismatch, a changed host key, a missing secret, or rejected
  credentials; once a session has been established, a rejection during an *automatic* reconnect is retried once
  before stopping, because the credentials worked before and one rejection is usually a server still coming up. A
  user Connect always starts fresh: routing is cleared and re-applied, while the listener keeps its port.
- If the configured host name stops resolving during a reconnect and the server's host key is known - pinned, trusted
  on first use, or verified earlier in this session - the address of the last successful session is tried before
  backing off; a different host answering there is treated as a stale address, not as a configuration error. The same
  goes for the protected address a reconnect with TUN held dials: another key there means the address is stale, it is
  forgotten, TUN is released and the next attempt resolves the name, where a changed key still stops everything.
- Every failure path ends in either a scheduled retry or an explicit halt. A 10-second watchdog checks that invariant
  (session wanted, not halted, but no client, no attempt in progress and no timer armed) and, if it ever fails, logs
  it as a supervisor bug and schedules the reconnect itself. An attempt that runs for more than five minutes is
  reported in the diagnostics as well.
- The diagnostics log records each attempt with its number and trigger, each scheduled retry with its delay, and the
  wake events that caused a probe.

## Xray profiles

The Xray transport runs proxy profiles imported from share links in the bundled Xray-core runtime
(`resources/xray/<platform>/<arch>/xray`, currently 26.3.27). Supported links:

- `vless://`, `vmess://` and `trojan://`;
- Hysteria 2: `hysteria2://` and its alias `hy2://`. The same link under either scheme is one profile. Hysteria v1
  (`hysteria://`) and `hysteria2+realm://` links are not supported.

Xray 26 removed the HTTP/2 (`type=h2`/`http`) and QUIC transports, so such links import as unsupported, and a profile
saved with HTTP/2 earlier is marked unsupported when the store loads. It also dropped mKCP's `header` and `seed`
settings, and with them the obfuscation every older mKCP server applies by default. An mKCP link's `headerType` and
`seed` (a v2rayN VMess link keeps the seed in `path`) therefore become `finalmask` UDP masks that write the same
packets: the fake header, then AES-128-GCM keyed by the seed, or the old XOR obfuscation without one. A link from an
Xray 26 panel describes its masks in `fm`, which then wins. The mask names follow the Xray version: `header-*`,
`mkcp-aes128gcm` and `mkcp-original` before 26.6.1 (including the bundled 26.3.27), `mkcp-legacy` from 26.6.1 on.

Hysteria 2 runs over QUIC, so it needs UDP to the server and to every hop port. The app reports Connected as soon as
Xray's local listeners are up, even when the network drops UDP; a failed post-connect tunnel check is the only sign,
and its message for a Hysteria 2 profile says so. The app can't tell which cause it was: Xray logs why a Hysteria 2
dial failed (auth refused, certificate error, timeout) at `[Info]`, below the `warning` level the app runs it at, so
that reason never reaches the Activity log. The hint names the usual suspects instead: blocked UDP, or a wrong
password (`auth`), `pinSHA256` or obfuscation password. While the latest tunnel check since connecting has failed,
Connect shows a Hysteria 2 session as "Check failed" in warning colours instead of "Protected" or "Proxy ready", and so
does the sidebar status card.

Port hopping comes from a port list in the link's authority (`hy2://auth@example.com:443,20000-30000`), from an
`mport` parameter (which takes precedence) or from the `fm` JSON. The list is sorted and merged
(`20000-30000,443,25000-35000` becomes `443,20000-35000`), may hold at most 64 ranges after merging, and is stored as
the profile's `hopPorts`. With a hop list, Xray starts on a random port from the list and moves to another one every
`hopInterval` (30 seconds by default, at least 5). The first port written in the authority is dialled only when the
link doesn't hop; the profile still keeps it as `port`, and the default name `hysteria2-<host>:<port>` uses it. With
the TUN adapter, that port and every hop port on the server address stay out of the tunnel (`protectedPorts`, see
`native/TUN_DATAPLANE.md`).

The hopping config depends on the Xray version, read with `xray version` and cached per binary until the file
changes: 26.9.9 and later get a `udphop` UDP mask, older releases (including the bundled 26.3.27) get
`finalmask.quicParams.udpHop`, and an unknown version gets the bundled shape. A version run that fails to start or
times out isn't cached, so the next connect asks again.

A link with `insecure=1` (or `allowInsecure=1`) asks to skip certificate checks, which the bundled Xray can't do: it
has no `allowInsecure`. A link with `insecure=1` and no `pinSHA256` still imports and can be selected, but the server
certificate is verified as usual: it works with a real certificate and fails with a self-signed one, and the app
warns about it. The profile stores this as `insecureWithoutPin` (whether it came from Add profile, Import links or the
public list), so its card and the Connect picker tag it `insecure=1`, the tray's server list shows it as
`Hysteria 2 · insecure=1`, Connect shows the warning before connecting, a failed tunnel check names it as the likely
cause, and every connect logs it. Put the certificate's SHA-256 in the link as `pinSHA256` (hex, colon-separated hex
or base64) to accept a self-signed certificate; with a pin, `insecure=1` is harmless. Profiles can't be edited, so the
pinned link is saved as a new profile; Add profile selects it for Connect in place of the selected tagged profile
with the same host and ports.

Only `salamander` obfuscation (with `obfs-password`) is supported; other obfuscation types and a malformed
`pinSHA256` are rejected at import. In `fm` (finalmask JSON), Shadow reads only a `salamander` mask, port hopping
(`quicParams.udpHop` or a `udphop` mask) and the other `quicParams`; any other UDP mask, including salamander with a
`packetSize`, is rejected at import. That is Shadow's choice, not a limit of the bundled Xray, which can run masks
such as noise or the header masks. An `ech` value must be a base64 ECHConfigList: the DNS-server forms Xray also
accepts (`udp://…`, `https://…`) are rejected, because Xray would query that server directly, outside the tunnel. A
host longer than 253 characters is rejected too.

Congestion control: Brutal runs only when the link sets an upload rate (`up`, or `brutalUp` in `fm`) and the server
accepts the client's bandwidth, at the lower of `up` and the server's limit. `down` is only a hint sent to the server.
Without `up`, or when the server doesn't accept client bandwidth (it answers "auto"), Xray uses BBR. A congestion
setting in `fm` (`bbr` or `reno`) overrides this.

Hysteria 2 `auth` and obfuscation passwords are redacted from diagnostics; certificate pins stay visible.

### Xray runtime lifecycle

- **Config:** passed on stdin (`xray run -config stdin:`), so profile credentials never reach the disk. A
  `xray/xray-config.json` (and its `*.tmp` files) left by an earlier version is deleted when the Xray bridge starts.
- **Local ports:** Xray's SOCKS and HTTP inbounds, which the app advertises as the local proxy, reuse the ports of the
  previous run for the lifetime of the app. A port that has been taken since gets an ephemeral one, and the local
  routing listener's port is never used for them.
- **Unexpected exit:** Xray is restarted with a backoff of 1 s doubling to 256 s, plus up to 5 s of jitter. A failed
  restart is rescheduled rather than ending in Error, a wake or network change brings the pending attempt forward, and
  Disconnect stops the cycle. A connect the user started that fails still ends in Error, and so does a restart that
  cannot work however often it is tried: the Xray runtime is missing (deleted or quarantined while it ran) or the
  config is refused. Routing held for it is then given back, and nothing more is scheduled.
- **Routing hold:** while Xray restarts, routing (adapter, local routing listener, system proxy) stays pointed at its
  ports for 30 s, as the SSH transport holds it while reconnecting. A restart within the hold takes it over in place;
  after the hold the machine is returned to direct routing until Xray is back. Dismissing the error releases it too.
- **Routing edits:** the local routing listener keeps running and its open connections stay up. The rules, and Xray's
  inbound after a restart, are swapped in place. The exception is a change to the rules for the local network on
  Windows (see the routing order below), which Xray reads only at start, while the Windows proxy points at Xray's
  HTTP inbound (the PAC or static path): Xray restarts, with routing held, and every connection it was carrying
  drops; only the direct ones stay up. What process discovery learned for the PAC is kept across that restart. Under
  the adapter or the routing listener, which reach Xray through its SOCKS inbound, the change is applied in place and
  Xray picks it up at its next start - or at once, when a later apply falls back to the proxy path.
- **TUN:** the adapter is told to send Xray's own process direct (`directProcesses`, by process ID), so Xray reaching
  its server on an address that was never protected cannot loop back into its own inbound. Another program called
  `xray.exe` - another client's own core - is routed like any other application.

## Storage

Normal data is stored in Electron `userData` under `storage/app-store.v1.json`.

Secrets are stored separately in `storage/secret-store.v1.json` and encrypted with Electron `safeStorage` when
available. On Windows, Electron `safeStorage` uses OS-backed protection. A local AES-GCM fallback exists only for
development environments where `safeStorage` is unavailable.

The store has a schema version so future migrations can be added without changing UI code.

## Native service and platform targets

The Go helper binaries are committed per platform and architecture. `npm run native:build-service` (part of
`package:prepare`) rebuilds them in place; `npm run dev` runs whatever is committed, so Go changes need a rebuild
before the app sees them:

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

Packaged builds ignore the developer switches listed in `PACKAGED_IGNORED_ENVIRONMENT_VARIABLES`
(`src/main/app/packaged-runtime.ts`): `VITE_DEV_SERVER_URL`, `SHADOW_SSH_BUILD_CHANNEL`, `SHADOW_SSH_XRAY_PATH`,
`SHADOW_SSH_SERVICE_ENDPOINT`, `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE`, `SHADOW_SSH_SERVICE_TOKEN` and
`SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK`. `SHADOW_SSH_USER_DATA_DIR` still applies.

The native binary supports `--stdio`, local endpoint mode, and Windows `--service` mode. Windows service install script
uses:

```text
shadow-ssh-service.exe --service --endpoint "\\.\pipe\shadow-ssh-service"
```

### Helper protocol

Electron talks to the `--stdio` helper in NDJSON (`src/service/local-ipc-protocol.ts`,
`native/service-go/internal/protocol`) and uses `get-capabilities`, `list-process-connections`, `start-dataplane`,
`stop-dataplane` and `recover-routes`. The Go side ignores JSON fields it doesn't know, so optional fields can be added
without breaking older binaries.

- `start-dataplane` takes an optional `directProcesses`: `[{"pid": <process ID>, "name": "<executable base name>"}]`,
  processes whose flows always go direct, right after the protected-endpoint check. A flow matches when its owner has
  that ID and, when a name is given, that name (compared case-insensitively). Only the Xray bridge sends it, for its
  running Xray child, so Xray's own connections to its server never loop back into its inbound; every Xray start
  applies routing again, so a restarted child's ID is sent too. Matching the ID, not the file name, keeps any other
  `xray.exe` on the machine under the user's rules.
- `recover-routes` (payload `{"journalPath": "…"}`, reply `{"recovered": <journal entries undone>}`) runs the same
  validated route-journal recovery a TUN start runs, without starting a dataplane, so routes left by a killed helper
  don't wait for the next TUN start. It needs elevation and fails on non-Windows builds. `get-capabilities` reports
  `routeRecovery: true` where the command exists; Electron checks it first, because older helper binaries lack it.
- When the TUN packet pump stops with a terminal error, the helper tears the dataplane down itself (route watcher,
  WFP guard, routes, adapter), writes one stderr line starting with `dataplane fatal:` and exits with status 3.
  Electron treats any unexpected helper exit while TUN is active as "TUN stopped unexpectedly". Both bridges then
  apply routing again at once (a fresh helper brings the adapter back, or the Windows proxy path takes over); after
  three such stops within ten minutes the session stays on the proxy path until the next Connect. If the session
  (or Xray) is down at that moment, routing is applied again only when it is back, and until then apps connect
  directly: the Windows proxy setting went when the adapter came up, so the routing hold has nothing left to hold.

## Routing

Routing modes:

- Full tunnel (`proxy-all`): all traffic goes through the tunnel. On Windows the local network (step 3 below) and
  sites on the Russian services list stay direct; elsewhere nothing reads the list or steers the system's traffic, and
  the local proxy tunnels everything apps send it.
- Split tunnel (`selected-rules`): only what the rules and the Blocked in Russia list select goes through the tunnel.

Split tunnel needs at least one enabled domain, IP/CIDR or process name rule, or the Blocked in Russia list. The
Russian services list alone doesn't count, because it only keeps sites direct. A rule for the local network - a private
range such as `10.0.0.0/8` or a `.local` name - counts like any other: it is how a user reaches the network behind the
server (step 2 below). The UI and main process both block Connect without a target.

Every path decides a connection in the same order: the TUN dataplane (`dataplane.Policy`), the local listener
(`LocalRoutingEnforcer.decide`), the generated PAC (`buildProxyPac`) and the TypeScript matchers. The first match
wins:

1. the transport's own server endpoint: direct, since routing it into its own tunnel would deadlock the transport;
2. an enabled domain or IP/CIDR rule: tunnel. An explicit rule wins, for the local network too: `10.0.0.0/8` or
   `corp.local` sends those destinations through the tunnel, to the network behind the server. Loopback is the
   exception on Windows: `localhost`, `127.0.0.0/8` and `::1` stay on this machine whatever a rule says - the static
   proxy's bypass always keeps `localhost` and `[::1]`, browsers and WinINet normally bypass loopback before the PAC is asked,
   loopback traffic never reaches the TUN adapter, and no domain rule can name `localhost` (a single label);
3. a local or private destination no rule named: direct. That is an IP literal in 127.0.0.0/8, ::1, 10.0.0.0/8,
   172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, fe80::/10, fc00::/7 or 0.0.0.0/8 (IPv4-mapped IPv6
   forms included), `localhost`, a single-label name without dots, or a name ending in `.local`;
4. an enabled `process.name` rule matching the process that owns the connection: tunnel. It comes after step 3: a
   process rule selects what an application sends to the internet, not its LAN traffic;
5. a destination on the Russian services list: direct;
6. Full tunnel: tunnel;
7. a destination on the Blocked in Russia list: tunnel;
8. anything else: direct.

A user rule therefore beats the local network and the Russian services list, and the list beats Full tunnel. An IP rule
matches a hostname through the addresses it resolves to on the PAC and listener paths; both look the name up only when
the answer would otherwise be direct. On the TUN path the list matches by the name a flow was learned or sniffed under
(see `native/TUN_DATAPLANE.md`) - a flow known only by learned names is released only when the list covers all of them,
and step 3 takes a name into account only when the flow named it itself - and flows of Shadow's running Xray process go
direct right after step 1 (`directProcesses`, matched by process ID). On the Windows proxy path (PAC or static proxy) the SSH listener
applies steps 2 and 3 itself, so a local destination a rule sent it is tunnelled and any other leaves directly. Anything
the TUN adapter hands it is tunnelled: the adapter has applied the whole order, and a private address a domain rule
picked through a learned name arrives as a bare address no rule can match there - sending it direct would take it out
of the tunnel and back into the adapter. On macOS and Linux, where apps are pointed at the listener by hand, it tunnels
everything too, as `ssh -D` does: the server's own network and its `localhost` are reached through it. The PAC-guessing
fallback for process rules never turns a learned local destination into a PAC rule, where it would rank with step 2.

Step 4 is the one the PAC cannot hold: it cannot tell which application asks. What process discovery learned for a
process rule is checked there after the direct list (step 5), so on that fallback a selected application's Russian
services sites stay direct, and process rules act in Split tunnel only. The TUN adapter and the local listener keep
step 4 where it is - and the TUN adapter applies it in Full tunnel too, so there an app rule sends that app's sites on
the Russian services list through the tunnel.

Xray's own routing keeps the local network direct as well, on Windows and only for its HTTP inbound - the one the
Windows proxy points at, for the static Full tunnel proxy whose bypass list names no address range. The SOCKS inbound,
which the TUN adapter and the routing listener use after applying the order themselves, and every inbound on macOS and
Linux, tunnel everything. The user's IP rules that overlap a local range and domain rules for `.local` names are put
ahead of that direct rule, to the tunnel (`xrayLocalRuleOverrides`), because everything that reaches Xray in Split
tunnel was already chosen upstream. Xray reads its config only at start, so on Windows a routing update that changes
that set, while the Windows proxy points at the HTTP inbound, restarts Xray through the same path as an unexpected
stop: routing stays pointed at its ports, which refuse connections meanwhile, and is taken over by the new process on
the same ports. Under the adapter or the routing listener the restart waits for the next Xray start, or for the first
apply that ends on the proxy path. Any other routing change is applied without a restart. With such an IP rule Xray resolves single-label and `.local` names, and only them, so the rule
selects them by the address they resolve to as the PAC and the SSH listener do (`domainStrategy` `IPOnDemand`; a name
rule ahead of every IP rule sends every other name to the tunnel by name, unresolved). Without one Xray stays on `AsIs`
and resolves nothing.

The static proxy (below) writes a `ProxyOverride` bypass - `<local>`, `localhost`, `*.local`, `[::1]` - which WinINet
applies before the proxy sees a connection, so a user rule for such a name could not win there. While a rule names
the local network the entries it needs are left out (`staticProxyOverride`): an IP rule that overlaps a local range
takes out `<local>` and `*.local`, a domain rule for a `.local` name takes out `*.local`. Those names then reach the
listener or Xray, which keep the ones no rule names direct themselves. Without such a rule the full bypass stays, so
intranet names take no detour through the loopback listener and stay in Windows' Local intranet zone. One gap is left
on that path: a single-label or `.local` name that only an IP rule for a public range selects still goes direct. IP
rules for literal addresses are not affected: the override names no address range.

The order is encoded in several places; change them together.

The default live SSH service starts a local HTTP/SOCKS listener after SSH auth succeeds. Traffic accepted by that
listener is forwarded through SSH `direct-tcpip` channels.

The Windows system-proxy/PAC path cannot attach a private credential to each loopback proxy request, so the ephemeral
HTTP/SOCKS listener is loopback-only but unauthenticated. On a shared/RDP host, another local OS user may be able to
discover and use that port; use this portable backend only with trusted local accounts. Strict per-user isolation
requires a privileged WFP dataplane, which is not bundled here.

On Windows, the app applies user-level system proxy settings while connected and restores the previous settings on
Disconnect/app quit:

- Full tunnel: with the Russian services list off, sets Windows HTTP/HTTPS/SOCKS proxy entries pointing at the
  local HTTP/SOCKS listener, with `ProxyOverride` set to `<local>`, `localhost`, `*.local` and `[::1]` alone (fewer
  while a rule names the local network, see above) - the
  user's own entries are put back on disconnect, but not kept meanwhile: the PAC ignores them, so a leftover `10.*` of
  another proxy tool would send hosts direct on one path that the other tunnels; with the list on, uses the PAC below
  so listed sites can stay direct. Private address ranges are not written as override
  wildcards, which WinINet would also match against public names such as `10.cdn.example.com`: the SSH listener and
  Xray's routing send those addresses direct themselves unless a user rule names them.
- Selected domain/IP rules: writes a PAC file under the app data directory, serves it through a loopback HTTP PAC
  endpoint, and sets `AutoConfigURL` for enabled domain, exact IP, and IPv4 CIDR rules. The PAC resolves hostnames
  before CIDR checks so IP rules can match destinations reached by domain name. A plain domain rule such as
  `example.com` covers the domain and all of its subdomains, the same way curated proxy-list entries behave; write
  `*.example.com` to route only subdomains and leave the apex direct.
- Process-name rules (primary path, both transports): the bundled native helper attributes each accepted proxy
  connection to its owning process through `GetExtendedTcpTable`, so routing is decided where process identity is
  actually known. While this path is active the system proxy points all proxy-aware TCP at a local listener, and the
  listener evaluates domain, IP and process rules together per connection: matching traffic enters the tunnel
  (SSH `direct-tcpip`, or Xray's SOCKS inbound when the Xray transport is active) and everything else leaves the machine
  directly, exactly as it would with the tunnel off. A `process.name` rule means *every* TCP destination that
  application reaches, so it is evaluated ahead of the curated direct list and the direct list is applied on the
  listener rather than in the PAC - a PAC entry would run before the listener and silently carve holes in the selected
  application's traffic. Only the transport's own server endpoint and the local network no user rule names (steps 1 and
  3 of the shared order: loopback, private, link-local and CGNAT addresses, `localhost`, single-label and `.local`
  names) stay excluded - the first because routing it into the tunnel it carries would deadlock the transport, the
  second because a process rule is about the application's internet traffic. Domain and process rules therefore apply
  simultaneously, and a selected application is covered completely - including hosts no rule names, DoH clients that
  never populate the Windows DNS cache, and destinations discovered after connect. The helper is read-only and never
  carries traffic.
- Process-name rules (fallback when the native helper is unavailable): Windows PAC/system proxy has no process context, so the portable backend watches Windows TCP
  connections for enabled process names, adds matched public remote IPs as temporary rules, and converts local DNS-cache
  matches into exact-domain rules. Learned IP and hostname routes are held for the connected session and refreshed on
  every discovery cycle rather than expiring with the DNS record TTL, because a destination stops being observable as
  soon as it is routed through the loopback proxy. An unambiguous tuple is additionally retained as an exact session
  route, so short-lived sockets cannot leave the PAC without a route. Both transports run the same learning
  (`src/service/process-route-learning.ts`); each decides when to publish what it learned.
  Shared IPs, multiple aliases, private/special-use addresses, and direct-list conflicts stay on conservative bounded
  fallbacks. A learned address stands for the process rule (step 4), so the PAC matches a name that resolves to it
  only after the local network and the direct list: a direct-list site on that address stays direct for every
  application, while the address as written, and any other name on it, is still tunnelled.
  Reviewed bootstrap host families are included for applications such as Discord whose critical API/CDN/WebSocket
  sockets otherwise disappear behind the loopback proxy. Other destinations remain `DIRECT`; already-open target
  sockets may need reconnect, and strict per-process enforcement still requires WFP/TUN.

The fallback process mode is best-effort TCP/system-proxy routing: PAC destination rules are global once learned, and an
application may place network sockets in a helper executable with a different name. Raw sockets, custom proxy/DNS
stacks, QUIC, and clients that ignore the Windows user proxy can bypass this path; add the network-owning helper name
or explicit domain rules when needed.

Both process modes still depend on the application honouring the Windows user proxy. An application that places its
sockets in a helper executable is matched by that helper's name, so add it when the parent name alone does not cover
the traffic. Raw sockets, custom proxy stacks and QUIC/UDP remain outside this path in either mode.

The SSH transport is TCP-only: SSH has no datagram channel, so UDP traffic is not proxied over SSH. This means
application UI/API/WebSocket traffic can use process routing, while UDP-only voice/video paths (including Discord
voice) remain outside the SSH tunnel. The Xray transport does carry the UDP it receives (its SOCKS inbound accepts
`UDP ASSOCIATE`, and the TUN adapter hands it UDP flows), and Hysteria 2 profiles need UDP themselves to reach their
server (see [Xray profiles](#xray-profiles)).

A tunnel adapter (TUN, Windows, the app started as administrator with `wintun.dll` present; see
`native/TUN_DATAPLANE.md`) captures traffic at the routing table instead, so process rules also reach applications
that ignore the Windows proxy setting. On that path a domain rule is matched by the name the connection itself
carries - the TLS ClientHello SNI, the HTTP `Host` header, or the ClientHello inside a QUIC Initial packet - in
addition to the DNS answers the adapter sees, so a browser that resolved a site before the tunnel came up, or resolves
over DNS-over-HTTPS, is still routed by its domain rules. Without the adapter the interception path is TCP over the
HTTP/SOCKS system proxy/PAC plus live SSH `direct-tcpip`, with process-name rules enforced by the local listener or,
failing that, the dynamic process destination PAC behavior described above.

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
native/          Go helper source (service-go), its committed binaries by OS and architecture, TUN notes.
scripts/         PowerShell and POSIX workflow scripts.
tests/           Focused validation tests.
```
