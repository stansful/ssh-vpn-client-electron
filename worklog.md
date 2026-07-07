# Worklog

## 2026-07-07

### Start: Proxy tunnel error diagnostics

- User provided logs where SSH eventually connects, Windows PAC routing applies, then diagnostics show bare `Connection refused` warnings without the refused target.
- Current focus: add target/protocol context to local HTTP/SOCKS proxy tunnel failures and clean misleading SSH connect diagnostics for password auth.

### End: Proxy tunnel error diagnostics

- Added target/protocol context to local HTTP/SOCKS proxy tunnel failures.
  - Example after fix: `HTTP CONNECT tunnel failed for refused.example:443: Connection refused`.
- Kept handshake errors unchanged when no target has been parsed yet.
- Changed live SSH connect diagnostics from `passphrase=...` to `passphraseProvided=...`, so boolean diagnostics are not redacted as secrets.
- Changed SSH TCP connect timeout text to include `host:port`.
- Added regression coverage for proxy tunnel error formatting.
- Verification passed: `npm run typecheck`, `npm test -- tests/network-proxy.test.ts`, `npm run lint`, full `npm test` (17 files, 103 tests), `npm run build`, and `git diff --check`.
- No dev server or long-running app process was started for this fix.

## 2026-07-04

### Start: Routing source link action

- User requested making the Routing source open `https://github.com/itdoginfo/allow-domains/tree/main/Russia`.
- User requested adding a copy button to the right, matching the existing GitHub link/copy pattern.
- Current focus: add the source row to Routing, wire open/copy actions, and allow the exact external source URL in main-process validation.

### End: Routing source link action

- Added a compact Source row to the Routing domain-list panel.
- Clicking Source opens `https://github.com/itdoginfo/allow-domains/tree/main/Russia`.
- Added a right-side copy button that copies the same source URL and shows a notice.
- Extended main-process external URL validation to allow only the exact routing source URL in addition to the app repository URL.
- Verification passed: `npm run typecheck`, `npm run build`, and `git diff --check`.
- No dev server or long-running app process was started for this UI change.

### Start: Routing domain list duplicate cards cleanup

- User pointed out that the `Proxy domains` / `Direct domains` cards duplicate information already shown in the domain-list rows.
- Current focus: remove the redundant facts cards from the Routing domain-list panel.

### End: Routing domain list duplicate cards cleanup

- Removed the duplicate `Proxy domains` / `Direct domains` facts cards from the Routing domain-list panel.
- Kept per-list counts in the `Russia inside-raw.lst` and `Russia outside-raw.lst` rows.
- Verification passed: `npm run typecheck`, `npm run build`, and `git diff --check`.
- No dev server or long-running app process was started for this cleanup.

### Start: Routing list modal visibility fix

- User reported that clicking `Russia inside-raw.lst` / `Russia outside-raw.lst` only blurs the app background and does not show the domain text viewer.
- Current focus: fix modal layering/render target so the list viewer card appears above the blur overlay.

### End: Routing list modal visibility fix

- Updated shared `Modal` to render through a React portal into `document.body`, avoiding nested stacking-context issues from the page content.
- Added an explicit modal card z-index so the dialog appears above the blur backdrop.
- Verification passed: `npm run typecheck`, `npm run build`, and `git diff --check`.
- No dev server or long-running app process was started for this fix.

### Start: Russia direct list and list viewer UI

- User requested adding `outside-raw.lst` as a DIRECT list analogous to the existing proxy list.
- User requested clicking `Russia inside-raw.lst` / `Russia outside-raw.lst` to open a text view of domains, with the checkbox as a separate control.
- User requested removing the `Updated` UI element because refresh notices already show update state.
- Current focus: add persisted direct-list model, PAC DIRECT handling before proxy rules, list viewer modal, and routing UI cleanup.

### End: Russia direct list and list viewer UI

- Added persisted `routingDirectList` backed by `outside-raw.lst`, disabled by default.
- Added IPC/preload/renderer controls for enabling and refreshing the direct list.
- Updated SSH/Xray routing updates so both lists are passed to the Windows PAC layer:
  - `inside-raw.lst` stays a proxy-list and routes matching domains through the tunnel;
  - `outside-raw.lst` is a direct-list and returns `DIRECT` before proxy rules;
  - `proxy-all` now switches to PAC when direct-list domains are enabled, so direct exceptions can work.
- Updated Routing UI:
  - `Domain lists` now shows separate proxy/direct cards;
  - list names open a read-only text viewer with loaded domains;
  - checkboxes are separate `Use` controls;
  - removed the `Updated` facts row.
- Added storage and PAC tests for the direct list and direct-before-proxy ordering.
- Verification passed: `npm run typecheck`, targeted `npm test -- tests/network-proxy.test.ts tests/app-storage.test.ts tests/service-routing.test.ts`, `npm run lint`, full `npm test` (17 files, 102 tests), `npm run build`, and `git diff --check`.
- Process check note: no dev server was started; `pgrep`/`ps` process inspection is blocked in this sandbox (`sysmond service not found` / operation not permitted).

### Start: Russia inside proxy routing list correction

- User clarified that `inside-raw.lst` must be a proxy list, not a bypass/DIRECT list.
- Current focus: invert the previous list semantics, rename persisted/API/UI concepts from bypass to proxy list, and make selected-rules treat enabled list domains as proxy targets.

### End: Russia inside proxy routing list correction

- Corrected `inside-raw.lst` semantics from DIRECT bypass to proxy routing.
- Renamed app concepts from bypass to proxy list:
  - persisted store field is now `routingProxyList`;
  - IPC/API methods are now `updateRoutingProxyListEnabled` and `refreshRoutingProxyList`;
  - Routing UI now shows `Proxy list` and `proxied` domain counts.
- Added migration from the temporary erroneous `routingBypassList` field into `routingProxyList`.
- Updated Windows PAC generation so proxy-list domains join proxy conditions in selected-rules mode instead of returning `DIRECT`.
- `Selected rules` connect/blocking logic now allows an enabled proxy-list with domains even when there are no manual rules.
- Verification passed: `npm run typecheck`, `npm test -- tests/network-proxy.test.ts`, `npm test -- tests/app-storage.test.ts`, `npm test -- tests/service-routing.test.ts`, `npm run lint`, `npm test` (17 files, 99 tests), and `npm run build`.

## 2026-07-03

### Start: WSS over SSH disconnect fix

- User provided Firefox/WebSocket King screenshot showing WSS over SSH receives HTTP proxy `200 Connection Established`, sometimes reaches WebSocket `101`, then disconnects.
- Current focus: inspect SSH `direct-tcpip` channel lifecycle and local proxy byte pump for premature close/EOF handling on long-lived bidirectional WebSocket streams.

### End: WSS over SSH disconnect fix

- Hardened SSH `direct-tcpip` EOF handling for long-lived bidirectional streams:
  - SSH channel EOF is now treated as half-close (`end`) rather than immediate full close for direct TCP channels;
  - full channel cleanup remains tied to SSH channel close/open-failure;
  - local HTTP/SOCKS proxy now listens to channel `onEnd` separately from `onClose`.
- Updated channel lifecycle rules so local writes remain allowed after remote EOF until the local side sends EOF/CLOSE.
- Added regression coverage for directional EOF channel behavior.
- Verification passed: `npm run typecheck`, `npm test -- tests/ssh-transport-security.test.ts`, `npm test -- tests/network-proxy.test.ts`, `npm test -- tests/ssh-session-state.test.ts`, `npm run lint`, `npm test` (17 files, 98 tests), and `npm run build`.

### Start: SSH WebSocket proxy fix

- User reported that WebSocket traffic does not work at all when connected through SSH.
- Current focus: inspect the SSH local HTTP/SOCKS proxy path, especially HTTP Upgrade and CONNECT handling, then add regression coverage.

### End: SSH WebSocket proxy fix

- Fixed SSH local HTTP/SOCKS proxy parsing for absolute-form `ws://...` HTTP proxy requests.
- WebSocket HTTP Upgrade requests now preserve the original path/query when rewritten from proxy absolute-form to origin-form.
- Existing Upgrade-related headers remain intact; only `Proxy-Connection` is stripped as before.
- Added a regression test covering `GET ws://host/path?query HTTP/1.1` with `Upgrade: websocket`.
- Verification passed: `npm test -- tests/network-proxy.test.ts`, `npm run typecheck`, `npm run lint`, `npm test` (17 files, 94 tests), and `npm run build`.

### Start: Russia inside bypass routing list

- User requested adding support in Routing for the `itdoginfo/allow-domains` Russia `inside-raw.lst` list.
- Current focus: add an optional DIRECT bypass list sourced from the raw GitHub list, persist it locally, and apply it to SSH/Xray Windows PAC routing without changing normal routing defaults.

### End: Russia inside bypass routing list

- Added persisted `routingBypassList` with the Russia `inside-raw.lst` raw URL, disabled by default.
- Added Routing UI controls:
  - enable/disable `Russia inside-raw.lst`;
  - refresh the list from GitHub;
  - show domain count, last update time, and source.
- Added main-process refresh/parsing:
  - downloads the raw list with timeout/size limits;
  - parses whitespace-separated domains;
  - supports suffix entries like `.ua` and wildcard entries like `*.example.com`;
  - stores the normalized unique domain list locally.
- Added active routing re-apply after bypass toggle/refresh for both SSH and Xray.
- Extended Windows PAC generation:
  - bypass domains return `DIRECT` first;
  - `proxy-all` with bypass uses PAC so the bypass can work;
  - selected-rules still applies user proxy rules after bypass checks.
- Added parser, PAC, and storage default tests.
- Verification passed: `npm run typecheck`, `npm test -- tests/network-proxy.test.ts`, `npm test -- tests/app-storage.test.ts`, `npm run lint`, `npm test` (17 files, 97 tests), and `npm run build`.

### Start: startup auto-connect setting

- User requested a Settings toggle so app startup automatically reconnects to the previously used SSH/Xray transport without pressing Connect each time.
- The setting must default to enabled.
- Current focus: persist the setting and last successfully connected transport, add Settings UI, and run startup auto-connect in the main process after services initialize.

### End: startup auto-connect setting

- Added persisted `autoConnectOnStartup`, defaulting to `true`.
- Added persisted `lastConnectedTransport`, defaulting to `ssh` for new stores and migrating from legacy `activeGlobalTab` for old stores.
- Added Settings > Window toggle: `Auto-connect on app start`.
- Main process now attempts startup auto-connect after storage/service initialization:
  - reconnects to the last successfully used SSH/Xray transport;
  - skips cleanly without UI errors when no SSH config/Xray profile is selected;
  - skips selected-rules mode if there are no enabled routing rules;
  - logs startup auto-connect progress/failures without exposing secrets.
- Successful manual SSH/Xray connects now update `lastConnectedTransport` and bring Main back to the matching transport tab.
- Added storage tests for the new defaults and legacy migration.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 93 tests), and `npm run build`.

### Start: update download folder action

- User requested replacing the updater action `Open downloaded file` with `Open folder with file`.
- Current focus: reveal the downloaded portable artifact in its folder instead of launching the file directly.

### End: update download folder action

- Replaced the updater action with `Open folder with file` in Settings.
- Renamed the updater IPC/API method to `revealDownloadedUpdate`.
- Electron now uses `shell.showItemInFolder()` for the downloaded portable artifact instead of launching it.
- Verification passed: `npm run typecheck`, `npm run lint`, and `npm run build`.

### Start: SSH Main routing mode ordering

- User requested moving Main > SSH `Routing mode` below `Check tunnel endpoint`, matching the Xray tab ordering.
- Current focus: reorder the existing SSH Main fields without changing behavior.

### End: SSH Main routing mode ordering

- Moved Main > SSH `Routing mode` below the editable `Check tunnel endpoint` row to match Main > Xray.
- Verification passed: `npm run typecheck`, `npm run lint`, and `npm run build`.

### Start: Xray routing mode card width fix

- User reported that Main > Xray `Routing mode` does not fit correctly after previous UI cleanup.
- Current focus: make the remaining Xray routing-mode summary use the full available width instead of the generic two-column facts layout.

### End: Xray routing mode card width fix

- Added a `single-facts` layout variant and applied it to Main > Xray routing-mode summary.
- The Xray `Routing mode` card now spans the full connection panel width instead of occupying one half of the old two-column facts grid.
- Verification passed: `npm run typecheck`, `npm run lint`, and `npm run build`.

### Start: Windows startup-to-tray setting

- User requested a setting to auto-start the app with Windows in minimized-to-tray mode.
- Setting must be disabled by default.
- Current focus: add persisted setting, Settings UI toggle, Windows login-item synchronization, and startup argument handling so autostart launches hidden in tray.

### End: Windows startup-to-tray setting

- Added persisted `startWithWindowsInTray` setting, defaulting to `false`.
- Added Settings > Window toggle: `Start with Windows in tray`.
- Toggle is enabled only on Windows; non-Windows builds show it disabled.
- Added Windows login-item synchronization through Electron `app.setLoginItemSettings`.
- Startup registration uses the real portable executable path from `PORTABLE_EXECUTABLE_FILE` when available, falling back to `process.execPath`.
- Added `--shadow-ssh-start-minimized-to-tray` startup argument handling:
  - app creates the BrowserWindow hidden;
  - devtools are not opened for hidden startup;
  - tray remains available for hidden startup even if `Close to tray` is off.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 92 tests), and `npm run build`.

### Start: Main SSH/Xray routing and endpoint UI cleanup

- User requested showing the current Settings routing mode on Main > SSH.
- User requested making the check tunnel endpoint editable on Main > Xray, matching the SSH tab behavior.
- User requested removing the `Profiles` and `Pinned` summary cards from Main > Xray.
- Current focus: update Main tab presentation only, reusing the existing endpoint modal and persisted settings.

### End: Main SSH/Xray routing and endpoint UI cleanup

- Added the current routing mode row to Main > SSH, sourced from the global Settings routing mode.
- Added editable `Check tunnel endpoint` row to Main > Xray using the existing endpoint modal and saved setting.
- Removed the `Profiles` and `Pinned` summary cards from Main > Xray; profile management remains in the Xray profiles panel.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 92 tests), and `npm run build`.

### Start: routing reconnect loop fix and Xray naming

- User attached logs showing repeated SSH/Xray reconnects after changing routing mode while a tunnel is active.
- Log pattern shows controlled restarts are being interpreted as failures, especially Xray `SIGTERM`, which schedules reconnect again.
- User requested replacing OpenSource naming with Xray everywhere.
- Current focus: apply routing mode changes in-place for active tunnels, suppress self-induced reconnects, preserve persisted settings through migration, and rename user-facing OpenSource labels/messages to Xray.

### End: routing reconnect loop fix and Xray naming

- Fixed routing-mode changes while connected:
  - `updateRoutingMode` no longer calls full SSH/Xray `connect()` when a tunnel is active;
  - active SSH/Xray transports now re-apply system proxy/PAC routing in place with the existing local proxy endpoint;
  - switching to `Selected rules` with zero enabled rules still disconnects and surfaces an error, preserving the previous guard.
- Added service-side `updateRouting()` plumbing for in-process, local IPC, and native-process service bridges.
- Hardened controlled restarts:
  - SSH replacement disconnects no longer schedule reconnect from the expected close event;
  - Xray `SIGTERM` caused by our own stop/restart is no longer treated as runtime failure.
- Replaced user-facing `OpenSource` naming with `Xray` in UI labels, notices, runtime diagnostics, and renderer module names.
- Migrated persisted settings:
  - old `activeGlobalTab: "opensource"` becomes `"xray"`;
  - old `openSource...` risk fields are read into the new `xray...` settings.
- Added storage regression coverage for legacy OpenSource-to-Xray settings migration.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 92 tests), and `npm run build`.

### Start: sidebar GitHub link, collapsible navigation, and optimization pass

- User requested a bottom-left GitHub link for `stansful/ssh-vpn-client-electron` with icon/name opening the site and a copy button copying the URL.
- User requested the left navigation panel to be collapsible or icon-only with animation to free content space.
- User requested tech-debt cleanup plus performance/battery/memory/file-size optimization.
- Current focus: implement persistent collapsible sidebar UX, add GitHub affordance, reduce packaged runtime bloat where safe, and inspect hot paths for low-risk performance/memory fixes.

### End: sidebar GitHub link, collapsible navigation, and optimization pass

- Added a bottom-left GitHub repository action in the sidebar:
  - icon/name opens `https://github.com/stansful/ssh-vpn-client-electron`;
  - copy button copies the repository URL through main-process clipboard IPC.
- Added a main-process allowlist for external URLs so the renderer can only open the project GitHub URL through the new IPC surface.
- Added a persistent `settings.sidebarCollapsed` flag and an animated icon-only sidebar mode, with mobile layout safeguards so narrow windows keep readable navigation.
- Added accessible labels/titles/current-page state for compact sidebar navigation.
- Reduced packaged Xray resource weight by changing electron-builder filters to include only the executable runtime (`xray.exe`/`xray`) instead of also shipping unused `geoip.dat` and `geosite.dat`.
- Updated the Xray downloader so geo data files are optional via `--include-geo`; the default runtime download now installs only the executable needed by the current generated Xray config.
- Reduced background process-name routing polling from every 10 seconds to every 30 seconds for both SSH and Xray transports to lower idle CPU/battery overhead.
- Explicitly enabled Electron background throttling for the renderer window.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 91 tests), `npm run build`, and `npm run xray:ensure -- --all`.
- Packaging was not rerun in this pass to avoid the known long signing/electron-builder step; the next portable build will apply the smaller Xray resource filter.

### Start: upload/download stall hardening

- User reports intermittent stalls before file uploads start, and the same class of stall can happen during downloads.
- Current focus: inspect the local proxy byte-pump and SSH/Xray forwarding paths, then harden stream piping/backpressure/timeouts so large or idle-transfer setup does not hang indefinitely.

### End: upload/download stall hardening

- Fixed a SOCKS5 parser bug that could drop early application bytes when a client sent the SOCKS5 CONNECT request and the first TLS/HTTP payload in the same TCP chunk. This can manifest as uploads/downloads hanging before the transfer visibly starts.
- Added a regression test proving SOCKS5 early bytes are preserved as `initialData`.
- Added low-latency TCP socket configuration (`setNoDelay`, `setKeepAlive`) for local proxy sockets and the SSH TCP transport.
- Added a SOCKS/HTTP proxy handshake timeout so half-open or malformed proxy handshakes cannot hang forever before transfer setup.
- Added backpressure-aware socket writing for both `Socks5Proxy` and `LocalTcpProxy`:
  - waits for local socket drain when needed;
  - caps queued local-socket output to avoid unbounded memory growth;
  - waits for queued remote data to flush before ending the local socket.
- Increased live SSH operation timeout from 15 seconds to 60 seconds, reducing false timeouts while slow remote endpoints or large uploads wait for SSH channel window updates.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 91 tests), and `npm run build`.
- Rebuilt Windows portable artifacts with the stall hardening:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`;
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`.
- Checked for leftover Electron/Vite/electron-builder/signtool/shadow-ssh processes with `pgrep`; none were running.

### Start: routing mode live reconnect

- User reported that changing Settings > Routing mode between `Proxy all` and `Selected rules` does not affect the active connection until reconnect.
- Current focus: make routing mode changes apply to the active SSH/Xray lifecycle immediately, using reconnect or service-side routing reapply as appropriate.

### End: routing mode live reconnect

- Updated the main-process `updateRoutingMode` IPC handler so a changed routing mode reconnects the currently active transport when SSH/Xray is connected, connecting, or reconnecting.
- SSH mode changes reconnect through the existing SSH connect lifecycle; OpenSource mode changes reconnect through the Xray connect lifecycle.
- If the user switches to `Selected rules` with zero enabled rules while connected, the active tunnel is disconnected and an error is surfaced instead of leaving stale `Proxy all` routing active.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 90 tests), and `npm run build`.
- Checked for leftover Electron/Vite/electron-builder/signtool/shadow-ssh processes with `pgrep`; none were running.

### Start: macOS/Linux Xray runtime packaging fix

- User hit packaging preflight while running macOS portable packaging: `resources/xray/macos/x64/xray` was missing.
- Current focus: download official Xray runtime binaries for the remaining macOS/Linux x64/arm64 targets and verify macOS packaging passes with embedded runtime.

### End: macOS/Linux Xray runtime packaging fix

- Ran `npm run xray:download-all` and installed official Xray-core `v26.3.27` runtime binaries for all supported desktop targets:
  - Windows x64/arm64;
  - macOS x64/arm64;
  - Linux x64/arm64.
- Verified runtime preflight with `npm run xray:ensure -- --all`.
- Re-ran `npm run pack:portable-mac`; macOS x64 and arm64 `.app` directory packaging now passes and includes embedded Xray runtime.
- Ran `npm run pack:portable-linux`; Linux x64 and arm64 AppImage packaging also passes and includes embedded Xray runtime.
- Produced Linux artifacts:
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`;
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`.
- macOS packaging is unsigned as expected on this host because no Developer ID identity is installed.
- Checked for leftover Electron/Vite/electron-builder/signtool/shadow-ssh processes with `pgrep`; none were running.

### Start: bundled Xray runtime and routing mode settings move

- User reported packaged Windows portable cannot find Xray at `resources/xray/windows/x64/xray.exe` after extraction.
- User asked to embed Xray into the portable exe.
- User asked to move the now-global `Routing mode` selector from Main to Settings.
- Current focus: inspect current resource packaging/runtime lookup, make Xray packaging preflight explicit, add a supported way to bundle runtime binaries into artifacts, and move routing mode control into Settings without changing routing behavior.

### End: bundled Xray runtime and routing mode settings move

- Confirmed `resources/xray/...` only contained placeholder `.gitkeep` files, so previous portable builds had no real Xray binary to embed.
- Added Xray runtime tooling:
  - `npm run xray:download` for a specific/current target;
  - `npm run xray:download-win` for Windows x64/arm64;
  - `npm run xray:download-all` for all supported desktop targets;
  - `npm run xray:ensure` for packaging preflight checks.
- Added electron-builder preflight in `scripts/electron-builder-with-local-dist.mjs` so packaging fails early if the target Xray runtime is missing instead of producing an exe that fails at runtime.
- Downloaded official Xray-core `v26.3.27` Windows runtimes and installed:
  - `resources/xray/windows/x64/xray.exe`, `geoip.dat`, `geosite.dat`;
  - `resources/xray/windows/arm64/xray.exe`, `geoip.dat`, `geosite.dat`.
- Moved the global `Routing mode` segmented control from Main to Settings > Routing.
- Removed the redundant Main routing facts/control surface while keeping selected-rules blocking logic intact.
- Checks passed: `npm run xray:ensure -- --target windows/x64 --target windows/arm64`, `npm run typecheck`, `npm run lint`, `npm test` (17 files, 90 tests), and `npm run build`.
- Packaging verification passed:
  - `npm run pack:win-dir-x64`;
  - `npm run pack:win-exe-x64`;
  - `npm run pack:win-exe-arm64`;
  - verified `release/win-unpacked/resources/xray/windows/x64/xray.exe`;
  - verified `release/win-arm64-unpacked/resources/xray/windows/arm64/xray.exe`;
  - rebuilt `release/shadow-ssh-0.1.0-windows-portable-x64.exe` with embedded Xray runtime;
  - rebuilt `release/shadow-ssh-0.1.0-windows-portable-arm64.exe` with embedded Xray runtime.
- Checked for leftover Electron/Vite/electron-builder/signtool/shadow-ssh processes with `pgrep`; none were running.

### Start: Main unused facts cleanup

- User pointed at the Main facts row with `Check endpoint` and `Reconnect attempts` and asked to remove it from the UI because it is unused.
- Current focus: remove the redundant Main facts without touching the underlying endpoint/reconnect runtime data.

### End: Main unused facts cleanup

- Removed the redundant `Check endpoint` and `Reconnect attempts` cards from the Main facts grid.
- Kept the editable check endpoint control and runtime reconnect data intact.
- Checks passed: `npm run typecheck`, `npm run lint`, and `npm run build`.
- Checked for leftover Electron/Vite/electron-builder/shadow-ssh processes with `pgrep`; none were running.

### Start: OpenSource transport support and Main transport switch

- User reported OpenSource profiles with `xhttp` are blocked as unsupported and asked to add support, plus broader protocol/transport support.
- User asked to move the SSH/OpenSource choice inside the Main tab instead of showing OpenSource as a separate left-sidebar item.
- Current focus: expand Xray stream config generation for currently parsed transports, remove the sidebar OpenSource entry, and add a Main-level transport switch that renders SSH or OpenSource connection UI.

### End: OpenSource transport support and Main transport switch

- Removed the hard UI/core block that treated `xhttp`, `httpupgrade`, `mkcp`, and `hysteria` as unsupported OpenSource/Xray transports.
- Expanded Xray stream config generation:
  - `xhttpSettings` with `host`, `path`, and `mode`;
  - `httpupgradeSettings` with `host` and `path`;
  - `kcpSettings` for `mkcp`/`kcp`, including `seed` and `headerType`;
  - `httpSettings` for `http`/`h2` transport aliases;
  - best-effort `hysteriaSettings` for parsed Hysteria transport parameters.
- Added transport alias normalization for `kcp -> mkcp`, `h2/http2 -> http`, and `http_upgrade/http-upgrade -> httpupgrade`.
- Moved the SSH/OpenSource selection into the Main tab using the persisted `settings.activeGlobalTab` setting.
- Removed the OpenSource item from the left sidebar and removed it from the renderer `View` route type/labels.
- Kept SSH and OpenSource runtime controls separated inside Main so an active Xray session is not displayed as an SSH connection.
- Added regression tests for parser alias normalization and Xray config generation for XHTTP, HTTPUpgrade, KCP, and HTTP/H2 transports.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 90 tests), and `npm run build`.
- Checked for leftover Electron/Vite/electron-builder/shadow-ssh processes with `pgrep`; none were running.

### Start: renderer SOLID split and large-file cleanup

- User pointed out that `src/renderer/App.tsx` is about 800 lines and asked to split similar places according to SOLID/patterns.
- Initial size scan shows the largest files are `src/main/main.ts`, `src/renderer/App.tsx`, SSH/Xray service/core files, and storage.
- Current focus: safely split the renderer orchestration first into feature hooks/components so `App.tsx` becomes a small composition root, then re-run typecheck/lint/tests/build before touching backend-heavy files.

### End: renderer SOLID split and large-file cleanup

- Reduced `src/renderer/App.tsx` from 794 lines to 109 lines. It is now a composition root that wires shell, hooks, views, and modals.
- Split renderer orchestration into feature hooks:
  - `useSnapshot`, `useAsyncAction`, `useRoutingController`, `useSshEntitiesController`, `useEndpointController`, `useTerminalController`, `useLogsController`, `useOpenSourceController`, and `useUpdateController`.
- Split renderer app composition into `components/app/AppViews.tsx` and `components/app/AppModals.tsx`.
- Reduced `src/main/main.ts` from 979 lines to 700 lines by extracting:
  - `app/main-window.ts` for BrowserWindow lifecycle and renderer mount diagnostics;
  - `app/paths.ts` for user-data and Xray binary path resolution;
  - `app/runtime-format.ts` for packaged path/url formatting and startup error HTML;
  - `app/public-proxy-refresh.ts` for manual public config refresh;
  - `app/portable-update-controller.ts` for portable update state/check/download logic.
- Reduced `src/service/xray-service.ts` from 617 lines to 490 lines by extracting process helpers into `service/xray/process-utils.ts` and SOCKS check helpers into `core/network/socks5-check.ts`.
- Left the remaining large protocol/core files (`live-client`, `live-ssh-service`, `socks5-proxy`, `session-state`, storage) intact for now because they need narrower protocol/storage-specific refactors with regression tests, not a broad move-only pass.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm test` (17 files, 88 tests), and `npm run build`.

### Start: desktop updater and OpenSource proxy transport

- User approved a custom GitHub updater for portable Windows `.exe` assets, initially Windows x64/arm64 only.
- User requested VLESS, VMess, and Trojan support, not VLESS-only.
- User requested the OpenSource/VLESS transport to preserve the current desktop business logic: mutual SSH/Xray transport lifecycle, existing routing modes/rules, checks, diagnostics, and graceful disconnect.
- User rejected periodic auto-sync, but requested a manual Refresh action that pulls public configs plus pinning and "delete all except pinned".
- Current focus: add shared proxy/update models, encrypted proxy profile storage, share-link parsers, manual public refresh, OpenSource UI tab, and an Xray child-process runtime path that reuses current local proxy/routing infrastructure.

### End: desktop updater and OpenSource proxy transport

- Added shared OpenSource proxy models for VLESS, VMess, and Trojan profiles, including protocol, transport/security metadata, encrypted raw URI storage, selected/pinned/stale flags, and import result reporting.
- Added share-link parsing for `vless://`, `vmess://`, and `trojan://`, plus Xray outbound/config generation for supported `tcp`, `ws`, and `grpc` transports with `none`, `tls`, and `reality` security modes.
- Added an Xray service bridge that starts a child Xray runtime, writes a service-side config under app user data, exposes local HTTP and SOCKS endpoints, routes Windows system proxy/PAC through the HTTP endpoint, keeps SOCKS for check-tunnel/direct use, reuses selected-rules flow, keeps SSH and Xray mutually exclusive, reconnects the Xray child process after unexpected exit, and restores routing on disconnect/delete/quit.
- Added production runtime path conventions without bundling heavy binaries by default: `SHADOW_SSH_XRAY_PATH` for development/override, and packaged `resources/xray/<platform>/<arch>/xray(.exe)` locations for Windows/macOS/Linux x64/arm64 when binaries are supplied.
- Added the OpenSource UI screen with Add profile, bulk Import links, manual Refresh public configs, pin/unpin, delete profile, delete all unpinned, selected-profile connect/disconnect, check tunnel, risk acknowledgement, and profile search.
- Optimized bulk OpenSource import and delete-unpinned secret persistence so Refresh/import does not rewrite the encrypted secret store once per profile.
- Added a custom GitHub portable updater for Windows x64/arm64 assets from `stansful/ssh-vpn-client-electron`, including SemVer comparison, release asset selection, ETag cache storage, trusted download URL checks, SHA-256 digest verification, and Settings controls for check/download/open downloaded file.
- Kept auto-sync disabled by design; public configs are pulled only by the Refresh button.
- Added tests for proxy share-link parsing, Xray config generation, unsupported transport rejection, and portable update asset/version handling.
- Checks passed: `npm run typecheck`, `npm test` (17 files, 88 tests), `npm run lint`, and `npm run build`.
- Note: actual OpenSource connection on a client requires real Xray binaries to be placed into `resources/xray/<platform>/<arch>/` or supplied through `SHADOW_SSH_XRAY_PATH`; the repo now has placeholder directories so packaging paths are stable.

### Start: tray icon packaged path fix

- User reported the Windows tray entry has a tooltip but no visible icon.
- Current focus: fix packaged tray icon path resolution so it reads unpacked resources from `process.resourcesPath`, and use a Windows `.ico` tray candidate before PNG fallback.

### End: tray icon packaged path fix

- Fixed packaged tray icon path resolution: it now uses `process.resourcesPath/icons/...` instead of a path inside `app.asar`.
- Added Windows tray icon candidates in order: `icon.ico`, then `icon.png`.
- Added `resources/icons/icon.ico` to Windows `extraResources` so the packaged app has an unpacked ICO file for the notification area.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm run build`, and `npm run pack:portable-win-exe`.
- Verified packaged Windows resources contain:
  - `release/win-unpacked/resources/icons/icon.ico`
  - `release/win-unpacked/resources/icons/icon.png`
  - `release/win-arm64-unpacked/resources/icons/icon.ico`
  - `release/win-arm64-unpacked/resources/icons/icon.png`
- Rebuilt Windows portable artifacts:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
- Checked for leftover Electron/electron-builder/Vite/native build processes after packaging; only the process check command itself was present.

### Start: root scrollbar and Settings performance cleanup

- User reported the visible scrollbar still uses the default system style, likely from Electron/viewport scrolling.
- User asked to remove the textual Performance information from Settings.
- Current focus: prevent root/body viewport scrolling, keep scrolling inside themed app content, and remove the Performance panel from Settings.

### End: root scrollbar and Settings performance cleanup

- Disabled root/body viewport scrolling by making `html`, `body`, and `#root` fixed to the renderer viewport with `overflow: hidden`.
- Moved app scrolling to `.content` with `overflow-y: auto`, so visible scrollbars use the app theme styles instead of the system body scrollbar.
- Removed the Settings Performance panel and deleted its unused CSS.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm run build`, and `npm run pack:portable-win-exe`.
- Rebuilt Windows portable artifacts:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
- Checked for leftover Electron/electron-builder/Vite/native build processes after packaging; only the process check command itself was present.

### Start: full-width check tunnel endpoint row

- User reported the `Check tunnel endpoint` row on Main does not open/stretch across the available window width.
- Current focus: remove the stale fixed max-width from the endpoint summary row and make the Main panel rows use the full available card width.

### End: full-width check tunnel endpoint row

- Removed the stale `.endpoint-summary { max-width: 520px; }` constraint.
- Made `.screen`, `.main-grid`, `.endpoint-summary`, and `.endpoint-line` use full available width.
- Made the endpoint value flex while keeping the `Edit` button fixed-width, so long endpoints wrap inside the row instead of shrinking the layout.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm run build`, and `npm run pack:portable-win-exe`.
- Rebuilt Windows portable artifacts:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
- Checked for leftover Electron/electron-builder/Vite/native build processes after packaging; only the process check command itself was present.

### Start: minimal default window and themed scrollbars

- User requested the app to open at its minimal window size by default.
- User reported default system scrollbars appear in some places and asked to style them to match the app.
- Current focus: align the BrowserWindow startup size with the existing minimum window constraints and add theme-aware global scrollbar styling.

### End: minimal default window and themed scrollbars

- Changed the Electron BrowserWindow default size from `1240x820` to the existing minimum supported size `980x680`.
- Added named default window-size constants so startup size and minimum constraints stay aligned.
- Added theme-aware global scrollbar styling for Chromium/WebKit and Firefox-compatible `scrollbar-color`/`scrollbar-width`.
- Scrollbar track/thumb colors now inherit app theme variables, including custom themes.
- Verification passed: `npm run typecheck`, `npm run lint`, `npm run build`, and `npm run pack:portable-win-exe`.
- Rebuilt Windows portable artifacts:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
- Checked for leftover Electron/electron-builder/Vite/native build processes after packaging; only the process check command itself was present.

### Start: remove transport badge, close-to-tray setting, and codebase structure split

- User requested removing the bottom-left `Live SSH` transport badge and related UI surface.
- User requested a setting: clicking the app close button should minimize/hide the app to the Windows hidden-icons/system-tray area using the app default icon; default should be enabled.
- User requested TSX files to be split into small atomic-design-style files/subfolders.
- User requested the same kind of small-file/folder refactor for the remaining code.
- Current focus: add the close-to-tray setting and main-process tray lifecycle first, then split renderer UI into views/forms/components/lib/types without changing behavior.

### End: remove transport badge, close-to-tray setting, and codebase structure split

- Removed the unused bottom-left `Live SSH` sidebar badge and deleted its CSS.
- Added default-enabled `closeToTrayEnabled` settings support and a Settings > Window toggle.
- Added main-process tray lifecycle:
  - close button hides the window when `Close to tray` is enabled;
  - tray icon uses the default application PNG;
  - tray menu supports `Show Shadow SSH` and `Quit`;
  - app quit still disposes the SSH/service bridge before exiting.
- Added unpacked `resources/icons/icon.png` extra resource for Windows/macOS/Linux packages so packaged tray icons resolve outside `app.asar`.
- Split renderer code into smaller folders/files:
  - `components/layout`, `components/main`, `components/configs`, `components/keys`, `components/routing`, `components/logs`, `components/settings`, `components/forms`, `components/ui`;
  - renderer helper logic moved to `src/renderer/lib`;
  - renderer draft/view types moved to `src/renderer/types.ts`.
- Removed obsolete `src/renderer/ui.tsx`.
- Verification:
  - `npm run typecheck` passed;
  - `npm run lint` passed;
  - `npm run test` passed: 14 files / 79 tests;
  - `npm run build` passed;
  - `npm run native:test-service` passed;
  - `npm run build:portable-win-exe` passed for Windows x64 and arm64;
  - `npm run pack:portable-win-exe` passed after tray icon resource packaging change;
  - verified `release/win-unpacked/resources/icons/icon.png` and `release/win-arm64-unpacked/resources/icons/icon.png` exist;
  - checked for leftover `electron-builder`, Vite, Electron, and native build/test processes; only the check command itself was present.

### Start: status pill sizing and routing autosave

- User reported the `Connected` status text is clipped inside the green status pill.
- User requested Routing page to autosave changes and remove the manual Save button.
- User also requested routing changes to apply to an active connection automatically, because newly added rules currently require reconnect before taking effect.
- Current focus: fix topbar/status layout, simplify Routing UX to autosave, and re-apply live system routing after rule changes while connected.

### End: status pill sizing and routing autosave

- Fixed topbar/status layout:
  - topbar now uses a `minmax(0, 1fr) max-content` grid so the status pill keeps its own column;
  - status pill now has enforced `min-width`/`min-inline-size`, no wrapping, and cannot shrink enough to clip `Connected`.
- Routing page:
  - removed the manual `Save` button;
  - add/toggle/delete/import now autosave routing rules immediately;
  - added a small `Autosave/Saving/Saved/Save failed` status indicator in the toolbar.
- Live routing application:
  - `LiveSshServiceBridge.updateRoutingRules()` now updates `lastRequest`;
  - when SSH is connected and SOCKS endpoint is active, changed rules re-apply system routing/PAC immediately;
  - process-name dynamic routing monitor is stopped/restarted as needed, and learned process IPs are cleared when process rules are no longer active.
- Browser preview verified:
  - status pill computes to 152px minimum width;
  - Routing toolbar has `Export`, `Import`, and `Autosave`, with no `Save` button.
- Checks passed: `npm run typecheck`, `npm run lint`, full `npm run test` (79 tests), and `npm run build`.
- Rebuilt Windows portable artifacts with `npm run build:portable-win-exe`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`

### Start: move Main check endpoint control below routing selector

- User reported the Main layout is still broken when `Check tunnel endpoint` sits next to the routing selector.
- Current focus: move the endpoint display/edit control into its own full-width row below routing mode so it cannot overlap the connection card.

### End: move Main check endpoint control below routing selector

- Moved `Check tunnel endpoint` out of the routing selector row and placed it below the Connect/Check tunnel action buttons as a separate full-width control.
- Kept the endpoint value as text plus `Edit` modal behavior.
- Adjusted `.main-routing-controls` to size only the routing selector, and constrained `.endpoint-summary` width so it stays inside the connection card.
- Browser preview verified endpoint is below routing and below action buttons, and its width remains within the connection panel.
- Checks passed: `npm run typecheck`, `npm run lint`, and `npm run build`.
- Rebuilt Windows portable artifacts with `npm run build:portable-win-exe`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`

### Start: SSH key modal errors, saved key copy, endpoint edit modal, and binary download proxy stability

- User reported SSH key validation errors appear outside the add/edit modal instead of inside it.
- User requested copying a saved private key while editing an SSH key.
- User reported Main layout regression around `Check tunnel endpoint`; requested text display plus an Edit modal instead of inline input.
- User reported media/images/archives/downloads fail over VPN while text works; attached logs show CONNECT tunnels opening, then occasional `read ECONNRESET`, `write after end`, and SSH disconnects during larger traffic.
- Current focus: keep modal-specific errors inside modals, add main-process clipboard copy for saved private keys, replace inline endpoint input with a modal, and inspect/fix proxy/channel byte pumping for larger binary streams.

### End: SSH key modal errors, saved key copy, endpoint edit modal, and binary download proxy stability

- SSH key modal errors:
  - config/key/endpoint modal saves now use modal-local error state instead of the global Main notice;
  - failed SSH key add/edit validation remains inside the SSH key modal.
- Saved private-key copy:
  - added `shadow-ssh:copy-private-key` IPC;
  - main process decrypts the stored private key and writes it directly to Electron clipboard;
  - renderer receives only success/failure, not the private key text;
  - edit SSH key modal now shows `Copy saved private key`.
- Main endpoint layout:
  - replaced the inline `Check tunnel endpoint` input with text plus an `Edit` button;
  - added `Edit tunnel check endpoint` modal with host:port validation;
  - Check tunnel now always uses the persisted endpoint value.
- Proxy/download stability:
  - added SSH channel data framing by remote `maximumPacketSize`;
  - direct-tcpip writes now wait for remote window availability and `WINDOW_ADJUST` instead of overfilling the channel;
  - per-channel writes are serialized to avoid concurrent remote-window races;
  - HTTP/SOCKS and local TCP proxy socket reads pause until the queued SSH channel write completes;
  - remote-to-local writes now check `writableEnded` to avoid `write after end`.
- Checks passed:
  - focused `npx vitest run tests/app-storage.test.ts tests/ssh-session-state.test.ts tests/network-proxy.test.ts`;
  - full `npm run test` (79 tests);
  - `npm run lint`;
  - `npm run typecheck`;
  - `npm run build`;
  - `npm run native:test-service`;
  - `npm run package:prepare`.
- Browser preview verified:
  - Main endpoint is text plus `Edit`;
  - endpoint modal validation stays inside the modal and does not create global notice;
  - SSH key edit modal contains `Copy saved private key`.
- Rebuilt Windows portable artifacts with `npm run build:portable-win-exe`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe` (~80 MB)
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe` (~74 MB)
- Verified packaged Windows `app.asar` contains the endpoint modal text, saved-key copy IPC, channel frame builder, max-packet guard, and `writableEnded` socket guards.

### Start: main routing controls, terminal defaults, logging visibility, key passphrases, theme colors, and performance pass

- User requested another UX/product pass:
  - terminal spoiler collapsed by default and auto-open shell after connect when expanded;
  - move routing mode and tunnel check endpoint from Settings to Main;
  - add logging switch in Settings and hide Logs nav when logging is off;
  - replace Disconnect square icon with an X;
  - move key passphrase ownership from SSH config to SSH key;
  - hide/edit key/password secrets with visibility/copy controls;
  - expand theme colors beyond accent/success/danger/surface;
  - improve performance/energy efficiency and check for leaks.
- Current focus: inspect defaults/storage/logging contracts, then implement the smallest safe migration and UI updates with verification.

### End: main routing controls, terminal defaults, logging visibility, key passphrases, theme colors, and performance pass

- Main screen:
  - terminal spoiler is collapsed by default for fresh runtime sessions;
  - if the terminal spoiler is opened while SSH is connected, the app opens the live shell automatically;
  - closing the spoiler closes the live shell channel without disconnecting SSH;
  - routing mode and tunnel check endpoint moved from Settings to Main;
  - Disconnect now uses an X icon instead of the old square stop icon.
- Logging:
  - added a master `Enable logs` switch in Settings;
  - when logs are disabled, runtime/file diagnostics stop being written and the Logs entry disappears from the sidebar;
  - bootstrap/main startup logging now reads the persisted `settings.loggingEnabled` flag before the first log write, so disabled logs do not create early startup log lines either;
  - in-memory diagnostics and terminal buffers are capped to avoid unbounded memory growth.
- Secrets and storage:
  - moved private-key passphrase ownership from SSH configs to SSH keys;
  - added storage migration for old config-level key passphrase secrets;
  - SSH key removal now deletes both the key secret and its passphrase secret;
  - SSH config password and SSH key/key-passphrase edit fields are masked by default with visibility/copy controls for the entered value.
- Theme and UX:
  - custom theme now includes background, surface, text, muted text, border, accent, success, and danger colors;
  - Settings includes a small Performance panel documenting event/memory/storage behavior.
- Performance changes:
  - renderer service events are applied incrementally instead of reloading the full snapshot on every diagnostic/terminal event;
  - tunnel endpoint edits are persisted on blur/Enter instead of each keystroke;
  - browser preview diagnostics/terminal buffers are capped too.
- Checks passed: focused `npx vitest run tests/app-storage.test.ts`, `npm run typecheck`, `npm run lint`, full `npm run test` (76 tests), `npm run native:test-service`, `npm run build`, and `npm run package:prepare`; after the early startup logging fix, re-ran `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`, and `npm run build:portable-win-exe`.
- Browser preview verified Main/Settings/config/key modal behavior, logging nav hiding, terminal collapsed default, routing controls on Main, and expanded theme controls.
- Rebuilt Windows portable artifacts with `npm run build:portable-win-exe`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe` (~80 MB)
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe` (~74 MB)

### Start: main UI cleanup, terminal behavior, modals, modern styling, and frontend refactor

- User requested broad UI/UX work:
  - remove duplicated Diagnostics block from Main;
  - make Main terminal open shell automatically when expanded and replace `Open shell` with `Close shell`;
  - make SSH config/key add/edit flows more user-friendly, likely modal-based;
  - add animations and modernize the whole UI;
  - replace custom theme editing with circular color-picking UI;
  - refactor frontend code structure and reduce UI tech debt.
- Current focus: inspect renderer structure, identify the smallest safe component split, then implement the UX changes with tests/build verification.

### End: main UI cleanup, terminal behavior, modals, modern styling, and frontend refactor

- Main screen:
  - removed the duplicated Diagnostics panel from Main;
  - kept diagnostics/log controls in the Logs view;
  - terminal panel now opens the SSH shell automatically when expanded;
  - removed `Open shell` and added `Close shell`, wired through real IPC/service/SSH channel close.
- SSH configs and SSH keys:
  - replaced inline edit forms with modal-based add/edit flows;
  - added explicit Cancel/Close actions;
  - added delete confirmations and empty-state primary actions.
- UI modernization:
  - added transitions, hover/focus states, screen/modal animations, shadows, and responsive layout behavior;
  - fixed narrow-preview layout by removing the old hard `body min-width` and adding responsive sidebar/content behavior;
  - replaced custom theme RGB number fields with a circular theme diagram plus four native color pickers.
- Code structure:
  - extracted shared renderer UI primitives into `src/renderer/ui.tsx`;
  - added `closeTerminal` across shared IPC, preload, browser preview API, service bridge, live SSH service, local/native process clients, standalone service host, and native Go service command handling;
  - added `SshLiveClient.closeShell()` to send SSH channel EOF/CLOSE for shell shutdown.
- Checks passed: `npm run test` (74 tests), `npm run lint`, `npm run typecheck`, `npm run native:test-service`, `npm run build`, and `npm run package:prepare`.
- Browser preview verified:
  - Main no longer contains Diagnostics;
  - config modal opens;
  - Settings contains the circular theme editor and four color pickers;
  - app shell width matches viewport after responsive fix.
- Rebuilt Windows portable artifacts with `npm run build:portable-win-exe`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`

### Start: selected process rules must not force proxy-all

- User rejected the previous portable fallback where any enabled `process.name` selected rule changed Windows system routing to proxy-all.
- Required behavior: enabled domain/IP rules go through the proxy, enabled `processname.exe` rules go through the proxy, and all other traffic remains direct.
- Current focus: remove the proxy-all fallback and implement a narrower portable Windows path for process rules without routing unrelated traffic through the tunnel.

### End: selected process rules must not force proxy-all

- Removed the `resolveWindowsSystemProxyMode()` behavior that changed selected-rules with process-name rules into proxy-all.
- Added Windows process connection discovery via PowerShell `Get-NetTCPConnection` + `Get-Process`.
- Added dynamic process-IP PAC augmentation:
  - selected routing stays `selected-rules`;
  - configured domain/IP rules remain active;
  - enabled `process.name` rules learn remote IPs from matching Windows processes and add those IPs as temporary PAC IP rules;
  - unrelated destinations remain `DIRECT` instead of being forced through the tunnel.
- Added a lightweight monitor that refreshes learned process IPs every 10 seconds only while connected and only when selected process-name rules exist.
- Learned process IPs expire after 5 minutes without being observed on a matching process connection, so stale process routes do not remain in PAC for the whole session.
- Added tests for process-IP rule augmentation and Windows process connection parsing.
- Updated README to remove the old proxy-all process fallback documentation and document the dynamic process-IP PAC behavior.
- Checks passed: focused `npx vitest run tests/service-routing.test.ts tests/windows-process-connections.test.ts tests/routing-core.test.ts`, full `npm run test` (74 tests), `npm run lint`, `npm run typecheck`, `npm run native:test-service`, and `npm run package:prepare`.
- Rebuilt Windows portable artifacts with `npm run build:portable-win-exe`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - verified packaged `app.asar` contains `windows-process-connections.js`, `learnedProcessIps`, and no old `resolveWindowsSystemProxyMode` fallback.

### Start: selected routing must work for domains and applications together

- User requested selected routing to work for domain rules and application/process rules at the same time.
- Current confirmed behavior: domain/IP selected rules work via Windows PAC/system proxy; process-name rules cannot be enforced by PAC because PAC has no process identity.
- Current focus: inspect existing native/service routing capabilities, then implement a Windows behavior that makes mixed selected rules operational instead of silently ignoring process-name rules.

### End: selected routing must work for domains and applications together

- Implemented a working portable Windows fallback for selected-rules containing any enabled `process.name` rule:
  - `resolveWindowsSystemProxyMode()` keeps domain/IP-only selected rules on PAC;
  - selected rules with process-name rules now apply the Windows HTTP/SOCKS system proxy backend (`proxy-all`) so application traffic actually goes through the SSH tunnel;
  - the app emits an explicit warning that this is a system proxy fallback and may proxy other Windows proxy-aware TCP traffic until WFP/TUN per-process routing is available;
  - process-only selected routing is no longer rejected before SSH connect.
- Updated service routing tests to cover process-only fallback, mixed domain/process fallback, domain-only PAC behavior, and non-Windows behavior.
- Updated README with the new process-rule fallback semantics.
- Checks passed: focused `npx vitest run tests/service-routing.test.ts tests/routing-core.test.ts`, full `npm run test` (73 tests), `npm run lint`, `npm run typecheck`, and `npm run native:test-service`.
- Rebuilt portable artifacts with `npm run build:portable-all`; verified Windows packaged `app.asar` contains `resolveWindowsSystemProxyMode`, `process fallback active`, and the new fallback diagnostic.

### Start: process-name selected routing case sensitivity check

- User confirmed domain selected routing works and asked whether application/process routing could fail because Windows process names are case-sensitive.
- Current understanding: portable Windows PAC/system-proxy backend cannot enforce process-name rules at all because PAC has URL/host context but no process identity. Case sensitivity may still matter in matcher/native paths, so verify and normalize process-name comparisons where applicable.

### End: process-name selected routing case sensitivity check

- Verified process-name matching is already case-insensitive in the TypeScript routing path:
  - `normalizeRuleValue("process.name", value)` lowercases rules;
  - `RoutingMatcher.match()` lowercases descriptor `processName`;
  - existing test `matches process names case-insensitively` covers `chrome.exe` matching `CHROME.EXE`.
- Verified native Go matcher also lowercases process rules and descriptors before comparison.
- Conclusion: application selected routing is not failing because of Windows case sensitivity. It does not work in the current portable Windows PAC/system-proxy backend because PAC has no process identity; only domain/IP selected rules can be enforced there. Process-name rules require WFP/TUN/connection attribution in the privileged/native routing layer or explicit per-app proxy configuration.

### Start: selected-rules PAC not applied and proxy log spam

- User confirmed proxy-all now works.
- New log shows proxy-all produces real `HTTP CONNECT ...` and `tunnel opened ...` entries, including `2ip.ru`, Telegram IPs, and YouTube/googlevideo hosts.
- In selected-rules mode the app reports `Windows PAC routing enabled`, but there are no browser `HTTP CONNECT ...` entries after PAC is enabled; only the explicit `Check tunnel` direct-tcpip test succeeds.
- User also asked to reduce log spam to protect SSD writes.
- Current focus: make selected-rules PAC delivery reliable on Windows and reduce high-volume proxy connection diagnostics written to file logs.

### End: selected-rules PAC not applied and proxy log spam

- Switched selected-rules PAC delivery from a `file://` PAC path to a loopback HTTP PAC server:
  - `WindowsSystemProxyManager` now serves `shadow-ssh-routing.pac` from `http://127.0.0.1:<port>/shadow-ssh-routing.pac`;
  - `AutoConfigURL` is set to that HTTP URL while connected;
  - the PAC server is stopped on restore/disconnect or when switching to proxy-all;
  - the PAC file is still written under app data for diagnostics/inspection.
- This addresses the log pattern where selected-rules claimed PAC was enabled but no browser traffic reached the local proxy at all.
- Reduced SSD log spam:
  - high-volume per-connection proxy diagnostics (`HTTP CONNECT ... from ...`, `tunnel opened ...`, routine handshake closes, `read ECONNRESET`, `write after end`) are still available in live diagnostics but are no longer forced into `main.log`;
  - important connect/disconnect/routing/check/error diagnostics remain persisted.
- Updated README to document loopback HTTP PAC delivery for selected rules.
- Checks passed: focused `npx vitest run tests/network-proxy.test.ts tests/service-routing.test.ts`, full `npm run test` (70 tests), `npm run lint`, `npm run typecheck`, and `npm run native:test-service`.
- Rebuilt portable artifacts with `npm run build:portable-all`; verified Windows packaged `app.asar` contains the PAC HTTP server, no `pathToFileURL` PAC usage, and the high-volume diagnostic filter.

### Start: intermittent settings write ENOENT after log cleanup

- User reported intermittent renderer error on the main screen: `shadow-ssh:update-settings` fails with `ENOENT` while renaming `storage/app-store.v1.json.<pid>.tmp` to `storage/app-store.v1.json`.
- User suspects it may happen after clearing logs.
- Current focus: inspect storage atomic-write logic and log cleanup/settings update concurrency, then make settings persistence resilient to overlapping writes and missing temp files.

### End: intermittent settings write ENOENT after log cleanup

- Root cause addressed: `writeJsonAtomic` used a process-wide temp path (`app-store.v1.json.<pid>.tmp`), so overlapping settings writes could race; one `rename` could consume the shared temp file while another pending write later tried to rename the same missing path.
- Updated storage persistence:
  - `app-store` writes and `secret-store` writes now each run through a per-file promise queue;
  - each atomic write uses a unique temp path containing `randomUUID()`;
  - failed writes clean up their own temp file and future queued writes keep working.
- Added `tests/app-storage.test.ts` covering concurrent atomic writes and concurrent `AppStorage.updateSettings()` calls.
- Checks passed: focused `npx vitest run tests/app-storage.test.ts`, full `npm run test` (70 tests), `npm run lint`, `npm run typecheck`, and `npm run native:test-service`.
- Rebuilt portable artifacts with `npm run build:portable-all` and verified packaged Windows `app.asar` contains `storePersistQueue`, `secretsPersistQueue`, unique temp naming, and temp cleanup.

### Start: Windows proxy enabled but browser traffic still does not reach SSH tunnel

- User provided a new unified log after testing a packaged Windows build.
- Latest relevant section shows SSH establishes, local `HTTP/SOCKS` proxy starts, Windows system proxy is enabled, and `Check tunnel` succeeds through SSH `direct-tcpip`.
- Browser/system traffic still fails with repeated `HTTP proxy socket closed during handshake` / `read ECONNRESET`, and there are no successful `HTTP CONNECT ...` / `tunnel opened ...` entries for browser destinations.
- Current focus: improve Windows system proxy application and proxy diagnostics so real browser requests reach the local listener correctly, while keeping handshake-close noise from hiding actionable proxy events.

### End: Windows proxy enabled but browser traffic still does not reach SSH tunnel

- Reworked proxy handshake parsing to use an internal `ProxySocketReader` buffer instead of `socket.unshift()`.
- Root cause addressed: when Windows/browser clients delivered `CONNECT ...` in one TCP chunk, the previous parser consumed the first byte and pushed the rest back with `socket.unshift()`. On real `net.Socket` flowing-mode timing, that buffered remainder could be missed before the HTTP parser installed its next listener, producing repeated `HTTP proxy socket closed during handshake` with no `HTTP CONNECT ...` diagnostics.
- The new reader keeps surplus bytes in memory across SOCKS5 and HTTP parsing, so one-chunk and split-chunk handshakes both parse deterministically.
- Added regression tests for one-chunk HTTP `CONNECT`, one-chunk SOCKS5 `CONNECT`, and retained the early HTTP CONNECT payload test. Test fake socket now fails if parser logic tries to depend on `socket.unshift()`.
- Updated README routing text from old SOCKS-only wording to the current HTTP/SOCKS listener behavior.
- Checks passed: focused `npx vitest run tests/network-proxy.test.ts`, full `npm run test` (68 tests), `npm run lint`, `npm run typecheck`, and `npm run native:test-service`.
- Rebuilt all portable artifacts with `npm run build:portable-all`; verified packaged Windows `app.asar` contains `ProxySocketReader` and no `socket.unshift` usage in `dist/core/network/socks5-proxy.js`.

### Start: proxy traffic still unusable after connect

- User reported that after connecting, nothing works.
- New log shows the latest hybrid proxy build is running: SSH session establishes, local HTTP/SOCKS proxy starts, Windows proxy is enabled, and `Check tunnel` through SSH direct-tcpip succeeds.
- The same log then shows no successful browser proxy diagnostics, only `HTTP proxy socket closed during handshake` and `read ECONNRESET`, which points to proxy client/proxy handshake or early connection lifecycle rather than SSH authentication/KEX.
- Current focus: make proxy diagnostics visible for successful connection/open/close events, handle HTTP CONNECT requests that carry early bytes after the CONNECT header, and avoid writing SOCKS failure bytes to HTTP clients.

### Start: portable build scripts must use local Electron runtimes

- While validating the previous `build:portable-all` fix, the command produced Windows `.exe` targets in the script but failed before packaging because electron-builder attempted to resolve `github.com` for Electron downloads.
- Manual per-architecture builds succeeded when `--config.electronDist=.cache/electron-<platform>-<arch>` was provided.
- Current focus: make npm portable scripts use the prepared local Electron runtimes for Windows/macOS/Linux x64 and arm64, so `npm run build:portable-all` builds the same artifacts without relying on network access during packaging.

### End: proxy traffic still unusable after connect

- Added service-side diagnostics for successful proxy lifecycle events, not only errors:
  - logs now include incoming `HTTP CONNECT` / `HTTP proxy` / `SOCKS5 CONNECT` requests with target host/port;
  - logs now include `tunnel opened` after SSH `direct-tcpip` channel creation succeeds;
  - repeated proxy info/warning events are capped per session to avoid log spam during browser reconnect loops.
- Fixed HTTP proxy error handling:
  - HTTP handshake failures now receive an HTTP `502 Bad Gateway` response instead of SOCKS failure bytes;
  - HTTP `CONNECT` requests that include early bytes after the header preserve and forward those bytes to the SSH channel.
- Added focused coverage for HTTP `CONNECT` early payload preservation.
- Checks passed: focused `npx vitest run tests/network-proxy.test.ts`, full `npm run test` (66 tests), `npm run lint`, `npm run native:test-service`, and `npm run package:prepare`.
- Rebuilt and verified Windows packaged `app.asar` contains the new proxy diagnostics, HTTP 502 handling, and early-byte forwarding.
- Note for next Windows validation: if browser traffic still fails, the unified log should now show the exact destination and whether the SSH `direct-tcpip` tunnel opens or fails for that request.

### End: portable build scripts must use local Electron runtimes

- Added `scripts/electron-builder-with-local-dist.mjs`, a small Electron Builder wrapper that uses `.cache/electron-<platform>-<arch>` when present and falls back to Electron Builder's normal download/cache behavior when the local runtime is missing.
- Updated npm packaging scripts to route through per-platform/per-architecture `pack:*` helpers using that wrapper.
- `npm run build:portable-all` now completes in this workspace without trying to resolve `github.com` during packaging because the local Electron runtimes are present.
- `build:portable-all`, `build:portable-win`, `build:portable-win-dir`, `build:portable-win-exe`, `build:portable-mac`, `build:portable-linux`, `build:installer-win`, `build:package-mac`, `build:package-linux`, and `build:dev-exe` now use the wrapper.
- Updated README to document the `.cache/electron-*` runtime behavior for portable/package scripts.
- Verified `npm run build:portable-all` produced:
  - `release/win-unpacked/Shadow SSH.exe`
  - `release/win-arm64-unpacked/Shadow SSH.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`

## 2026-07-02

### Start: Windows single-file EXE build target

- User reported that `build:portable-all` does not build a Windows `.exe`.
- Current state: Windows folder-portable builds do contain `Shadow SSH.exe` under `release/win-unpacked` and `release/win-arm64-unpacked`, but there is no single-file `.exe` in the `release/` root because the Electron Builder `portable` target was removed from default builds to avoid `%TEMP%` self-extraction.
- Current focus: add explicit Windows single-file EXE targets back as additional artifacts while preserving the no-Temp folder-portable Windows outputs.

### End: Windows single-file EXE build target

- Updated Windows build scripts in `package.json`:
  - `build:portable-all` now builds Windows folder-portable outputs and Windows single-file portable `.exe` outputs before macOS/Linux artifacts.
  - `build:portable-win` now builds both Windows folder and single-file outputs.
  - Added `build:portable-win-dir` for no-Temp folder-only Windows builds.
  - Added `build:portable-win-exe` for root `release/*.exe` single-file Windows builds.
  - `build:prod-exe` now points to `build:portable-win-exe`.
  - `build:dev-exe` again uses Electron Builder `portable` target.
- Restored Electron Builder `portable.artifactName` config for:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
- Updated README to document both Windows portable modes:
  - folder `.exe` under `release/win-unpacked` / `release/win-arm64-unpacked` for no `%TEMP%` self-extraction;
  - single-file `.exe` in `release/` for easier copying, with the explicit Electron Builder `%TEMP%` self-extraction caveat.
- Verified `package.json` parses, `npm run lint`, `npm run typecheck`, and `npm run test` pass.
- Built and verified root Windows single-file artifacts:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe` (80M)
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe` (73M)

### Start: hybrid proxy and unified log view

- User provided logs showing that SSH connects and terminal works, but proxy traffic does not work.
- Attached log shows repeated `Unsupported SOCKS version` and uncaught exceptions from `Socks5Proxy.handleSocket` after Windows system proxy is enabled.
- Current diagnosis: Windows/apps are reaching the local listener as an HTTP proxy/CONNECT endpoint, while the listener only accepts SOCKS5 and destroys sockets with errors during handshake.
- Current focus: make the local proxy accept both SOCKS5 and HTTP proxy/CONNECT traffic, prevent handshake errors from becoming uncaught exceptions, point Windows/PAC to the hybrid proxy, and simplify the Logs tab into one unified copyable log source.

### End: hybrid proxy and unified log view

- Fixed the proxy failure shown in the attached log:
  - local listener now accepts SOCKS5, HTTP `CONNECT`, and absolute-form HTTP proxy requests;
  - HTTP `CONNECT` returns `HTTP/1.1 200 Connection Established` and pumps bytes through SSH `direct-tcpip`;
  - absolute-form HTTP requests are rewritten to origin-form before forwarding to the destination through SSH;
  - unsupported/closed proxy handshakes no longer call `socket.destroy(error)` without an error listener, so they should not become `Uncaught exception: Unsupported SOCKS version`.
- Updated Windows proxy integration:
  - Proxy-all now writes `http=...;https=...;socks=...` into `ProxyServer`;
  - selected-rules PAC now returns `PROXY ...; SOCKS5 ...; SOCKS ...`, so Windows/browser clients can use HTTP proxy semantics first and SOCKS fallback if needed.
- Updated service diagnostics/status text from SOCKS-only to `HTTP/SOCKS proxy`.
- Simplified the Logs tab:
  - replaced separate runtime/file panels with one `Unified log` panel;
  - `Copy` reads the latest main log and copies one text source;
  - `Clear` clears both the file log and in-memory runtime diagnostics.
- Added tests for HTTP `CONNECT`, absolute-form HTTP proxy forwarding, and PAC `PROXY` output.
- Checks passed: `npm run lint`, `npm run typecheck`, focused `npx vitest run tests/network-proxy.test.ts`, full `npm run test` (65 tests), `npm run native:test-service`, and `npm run package:prepare`.
- Rebuilt release artifacts:
  - `release/win-unpacked/Shadow SSH.exe`
  - `release/win-arm64-unpacked/Shadow SSH.exe`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
- Verified packaged Windows `app.asar` contains the HTTP proxy parser, Windows `http/https/socks` proxy configuration, `HTTP/SOCKS` service diagnostics, and unified log UI.

### Start: selected IP/process routing and Windows proxy cleanup

- User confirmed live SSH connection now works.
- User reported that selected IP rules and process-name proxying still do not work.
- User also previously reported that ordinary internet can remain broken after Disconnect and requested removing runtime/log usage of the OS Temp directory.
- Current focus: move PAC storage out of Temp, harden Windows proxy restore/refresh, improve selected IP/CIDR PAC matching, and make process-name routing behavior explicit instead of silently implying PAC can match processes.

### End: selected IP/process routing and Windows proxy cleanup

- Moved Windows selected-rules PAC storage from the OS Temp directory to the app data routing directory (`%APPDATA%\Shadow SSH\routing` on Windows).
- Added persisted Windows proxy snapshots under the app data routing directory so Disconnect/app quit can restore `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`, and `AutoDetect`.
- Added WinINET refresh after apply/restore, plus existing WinHTTP import, to reduce cases where Windows keeps stale proxy settings after Disconnect.
- Hardened `stopRouting()` so proxy restore errors are logged but do not prevent SOCKS/session cleanup.
- Improved generated PAC for selected IP rules:
  - strips IPv6 URL brackets,
  - resolves hostnames with `dnsResolve`,
  - uses `dnsResolveEx` when available,
  - matches exact IPv4/IPv6 addresses,
  - uses the normalized IPv4 network address for CIDR checks.
- Made process-name selected routing explicit: Windows PAC/system proxy has no process context, so process-only selected mode is rejected before SSH connect instead of silently connecting without routing. Mixed domain/IP/process rules still connect; domain/IP rules apply and process rules emit a warning.
- Removed normal runtime Temp dependency from local IPC defaults on macOS/Linux; sockets now use `SHADOW_SSH_RUNTIME_DIR`, `XDG_RUNTIME_DIR`, or `~/.shadow-ssh/run`.
- Moved the macOS icon generation scratch directory from the OS Temp directory to the project `.cache`.
- Switched Windows portable production builds from Electron Builder single-file `portable.exe` to folder `dir` targets, because single-file portable EXEs self-extract to `%TEMP%` by design.
- Updated README build/routing docs for folder-portable Windows artifacts and process-name routing limitations.
- Added regression tests for DNS-resolved IP PAC generation and Windows process-only selected-route rejection.
- Checks passed: `npm run lint`, `npm run typecheck`, `npm run test` (63 tests), `npm run native:test-service`, and `npm run package:prepare`.
- Rebuilt release artifacts using cached local Electron distributions:
  - `release/win-unpacked/Shadow SSH.exe`
  - `release/win-arm64-unpacked/Shadow SSH.exe`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
- Verified packaged Windows `app.asar` contains the new PAC DNS/IP matching, app-data PAC path wiring, runtime socket path change, and process-only selected-route guard.

## 2026-06-09

### Start: continue desktop client implementation

- User requested keeping this worklog before and after work.
- Current baseline: Electron/TypeScript scaffold exists with UI, storage, validation, scripts, README, generated icons, tests, and simulator service.
- Next focus: continue moving the architecture toward the TZ by adding a real local IPC service boundary and a standalone service simulator process that can later be replaced by privileged Windows/macOS/Linux service binaries.

### End: local IPC service boundary

- Added `ServiceBridge` interface and JSON-line local IPC protocol.
- Added `LocalIpcServiceBridge` client for local-only socket/named-pipe service communication.
- Added standalone simulator service host at `src/service/service-host.ts`.
- Electron main now supports `SHADOW_SSH_SERVICE_ENDPOINT` and falls back to in-process simulator with a startup diagnostic warning if the endpoint is unavailable.
- Added `npm run build:node`, `npm run service:simulator`, `scripts/service-simulator.ps1`, IPC protocol tests, and README/native docs.
- Fixed service host socket cleanup so broadcasts do not write to closed client sockets.
- Verified local IPC manually with `get-status` and `shutdown` over a temporary Unix socket.
- Verified renderer preview at `http://127.0.0.1:5173/`.
- Checks passed: `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.

### Start: core protocol and routing implementation

- User asked to stop leaving dev/service processes running and to continue until the project functionality is complete.
- Stopped the previous `npm run dev` session before starting new work.
- Current missing production functionality: real custom SSH transport, privileged routing layer, Windows service installer/permissions, DNS/process/IP routing enforcement, and real tunnel checks through SSH.
- Next focus: add a reusable custom core foundation with SSH packet/crypto primitives, routing matcher logic, and stronger tests. This does not yet replace the future privileged OS routing implementation.

### End: core protocol and routing implementation

- Added own routing core with domain wildcard matching, process.name matching, IPv4/IPv6 parsing, CIDR network masking, and routing decisions.
- Added own SSH wire primitives: SSH binary reader/writer, mpint/name-list handling, packet framing, KEXINIT encode/decode, and version-line parsing/formatting.
- Included `src/core` in renderer/node TypeScript projects.
- Service simulator diagnostics now instantiate the routing core and SSH wire algorithm registry during Connect without logging secrets.
- Promoted service commands `update-config` and `update-routing-rules` from protocol-only to real `ServiceBridge` methods; Electron main now calls them after config/routing updates.
- Added tests for routing core and SSH wire primitives. Test count is now 4 files / 16 tests.
- Ran IPC smoke over a temporary local Unix socket: `get-status`, `update-routing-rules`, and `shutdown` succeeded.
- Stopped the temporary service process after smoke verification.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.
- Remaining production gaps: full SSH key exchange/auth/channel implementation, real privileged Windows routing/service installation, DNS visibility/domain-to-IP correlation, process-to-connection attribution, and UDP design.

## 2026-06-12

### Start: SSH core negotiation/auth/channel layer

- User asked to continue.
- No dev/service process should be left running after this stage.
- Current focus: extend the custom SSH core from wire primitives into reusable algorithm negotiation, Diffie-Hellman group14 SHA-256 key exchange primitives, host-key fingerprints, password/public-key auth request encoders, and channel/direct-tcpip/shell message encoders.
- This still will not be a complete production SSH client until encrypted transport, host-key verification flow, auth signing, channel state machines, and service routing are wired end to end.

### End: SSH core negotiation/auth/channel layer

- Added SSH algorithm negotiation helpers.
- Added host key fingerprint helpers for `SHA256:` and MD5-style fingerprints.
- Added Diffie-Hellman group14 SHA-256 client exchange primitives, KEXDH_INIT encoder, KEXDH_REPLY decoder, and exchange hash computation.
- Added service request, password auth request, public-key probe, and signed public-key auth request encoders.
- Added session channel, direct-tcpip channel, pty, shell, channel data, EOF, and close message encoders.
- Added SSH core tests for negotiation, fingerprints, DH shared secret, KEXDH messages, exchange hash, auth messages, and channel messages.
- README now documents the more detailed custom SSH core status and remaining SSH gaps.
- Updated `concurrently` to remove a critical transitive `shell-quote` audit finding.
- Checks passed: `npm run typecheck` via build, `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.
- Test count is now 5 files / 25 tests.
- No dev or service process was left running.

### Start: production SSH transport/security layer

- User asked to continue all the way toward full production functionality.
- No dev/service process should be left running.
- Current focus: implement production-critical SSH transport/security primitives: RFC 4253 key derivation, AES-CTR/HMAC packet protection, host-key blob parsing, signature verification, private-key signing, and channel state helpers.
- Remaining Windows production routing work will still require native privileged Windows API implementation and validation on Windows.

### End: production SSH transport/security layer

- Added RFC 4253 SSH key derivation helpers for IV, encryption keys, and integrity keys.
- Added AES-CTR + HMAC-SHA2 SSH packet protector/unprotector with sequence numbers and MAC verification.
- Added SSH host-key blob parsing for RSA and Ed25519 keys.
- Added SSH signature blob parsing/encoding and RSA/Ed25519 signature verification.
- Added private-key loading, SSH public-key auth signing payload construction, and signature blob creation.
- Added channel state manager for opening, open-confirm, remote window accounting, EOF, and close lifecycle.
- Service simulator now exercises algorithm negotiation and transport key length selection during Connect diagnostics.
- README updated with the current SSH core status.
- Added tests for key derivation, packet protection, tamper rejection, RSA/Ed25519 signature verification, private-key signing, and channel state.
- Checks passed: `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.
- Test count is now 6 files / 32 tests.
- No dev or service process was left running.
- Remaining production gaps: socket-driven encrypted SSH transport state machine, full auth/channel orchestration, real direct-tcpip forwarding loop, and native privileged Windows routing/service implementation.

### Start: SSH session state machine and channel orchestration

- User asked to continue toward production-ready functionality.
- No dev/service process should be left running.
- Current focus: add a deterministic SSH session state machine over the existing custom SSH primitives: KEX completion, NEWKEYS, service accept, password auth, auth failure/success, channel open confirmation/failure, window adjust, and channel data handling.
- Also fix packet protection to keep AES-CTR cipher state across packets instead of recreating it per packet.
- Remaining native Windows routing/service work still requires privileged Windows API implementation and Windows validation.

### End: SSH session state machine and channel orchestration

- Fixed SSH packet protection to keep AES-CTR cipher/decipher state across multiple packets.
- Added connection message decoders for NEWKEYS, service accept, auth failure/success, channel open confirmation/failure, window adjust, channel data, EOF, close, success, and failure.
- Added `SshSessionStateMachine` for KEX start, group14 negotiation, KEX completion hooks, NEWKEYS, userauth service request, password auth, auth result handling, session/direct-tcpip channel open, pty/shell requests, channel data, channel events, and channel state lookup.
- Constrained session state machine KEX list to supported `diffie-hellman-group14-sha256` until curve25519 is implemented.
- Added SSH public key blob export from Node `KeyObject` and signed public-key auth request builder.
- Added tests for persistent CTR stream state, group14 negotiation, NEWKEYS/service/password auth phase transitions, auth failures, direct-tcpip channel confirmation/window/data/close, SSH public key export, and signed public-key auth request structure.
- README updated with the current SSH session state status.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.
- Test count is now 7 files / 38 tests.
- No dev or service process was left running.
- Remaining production gaps: real socket I/O loop around the SSH state machine, encrypted packet stream reader/writer, direct-tcpip forwarding loop, and native privileged Windows routing/service implementation.

### Remaining production-ready functionality not yet implemented

SSH client/core:

- Real TCP socket connection to the SSH server.
- SSH identification exchange over the socket.
- Packet stream reader/writer that handles partial reads, packet length framing, encryption, MAC verification, sequence numbers, and disconnect/error packets.
- End-to-end KEX flow over the socket, including server KEXINIT, KEXDH reply, NEWKEYS, and rekey support.
- Curve25519 KEX implementation; current state machine only uses `diffie-hellman-group14-sha256`.
- Full host-key verification flow wired to `expectedServerFingerprint`.
- Password authentication over the live SSH transport.
- Private-key authentication over the live SSH transport, including passphrase handling and public-key auth signature generation.
- Auth failure handling with retry policy and user-facing errors.
- Interactive shell channel over the live SSH transport.
- Terminal PTY resize support.
- Direct TCP forwarding channel state machine over the live SSH transport.
- Direct TCP forwarding byte pump between local accepted sockets and SSH channels.
- Keepalive messages over SSH and detection of dead sessions.
- Reconnect loop that preserves user intent and rebuilds SSH/session/routing state after failures.
- Clean SSH disconnect messages and graceful channel shutdown.

Routing/networking core:

- Real local TCP listener/proxy entry points for forwarded connections.
- Windows traffic interception/routing layer.
- Proxy-all mode enforcement at OS/network layer.
- Selected-rules mode enforcement at OS/network layer.
- DNS visibility layer for domain rule matching.
- Domain-to-IP correlation cache with TTL handling.
- IPv4 route enforcement.
- IPv6 route enforcement.
- Process-name to connection attribution on Windows.
- Routing decision integration between intercepted traffic and `RoutingMatcher`.
- Loop-prevention so the protected SSH connection itself is never routed back into the tunnel.
- UDP support design and implementation, or explicit production-grade TCP-only enforcement.

Privileged service:

- Real Windows privileged service binary.
- Service install/uninstall/start/stop scripts or installer actions.
- Local-only IPC endpoint security/ACLs for Windows named pipes.
- Service command authorization so untrusted local users cannot control the tunnel.
- Service lifecycle integration with Electron main.
- Service diagnostics persistence/streaming without secrets.
- Native service packaging for `windows/x64` and `windows/arm64`.
- Future native service packaging for `macos/x64`, `macos/arm64`, `linux/x64`, and `linux/arm64`.

Storage/security:

- Service-side secret retrieval flow that does not expose secrets to renderer.
- End-to-end use of encrypted secrets during real SSH auth.
- Secret migration tests for future schema versions.
- Clear handling for unavailable secure storage backends in production.
- Private-key format parsing coverage for encrypted and unencrypted PEM/OpenSSH keys used in real auth.

UI/integration:

- UI connected to real SSH lifecycle instead of simulator status.
- Check tunnel through an SSH direct-tcpip connection, not direct TCP from the app process.
- Terminal panel connected to real shell channel output/input.
- Routing warning and blocking connected to actual service-side routing state.
- Process list on Windows using production-safe process enumeration.
- Import/export validation UX for malformed routing rule files.
- Settings and theme flows tested against persisted production storage.

Build/release:

- Windows development EXE build verified on Windows.
- Windows production EXE build verified on Windows.
- Code signing path verified with certificate env variables.
- Installer behavior for privileged service prompts verified.
- Production app icon verified in Windows artifacts.
- Release artifact locations and names verified.

Testing/validation:

- Integration tests for live SSH against a controlled test server.
- Integration tests for password auth.
- Integration tests for private-key auth and passphrase auth.
- Integration tests for direct-tcpip forwarding.
- Integration tests for shell terminal channel.
- Windows service IPC integration tests.
- Windows routing tests for proxy-all.
- Windows routing tests for selected domain/IP/process rules.
- Reconnect tests after forced SSH disconnect.
- Manual acceptance run on Windows for the original TZ criteria.

### Start: requested production functionality implementation

- User asked to implement the remaining SSH client/core, routing/networking, privileged service, storage/security, UI/integration, and build/release functionality.
- No dev/service process should be left running.
- Current focus for this pass: implement real SSH socket transport primitives, identification exchange, packet stream reader/writer, curve25519 KEX primitives, SSH client orchestration shell, local TCP proxy/direct-tcpip scaffolding, DNS cache, service-side secret access interfaces, Windows service script scaffolding, and tests/documentation.
- Windows traffic interception, route manipulation, process attribution, service ACL hardening, installer prompts, and Windows artifact verification still require Windows-specific implementation and validation on Windows.

### End: requested production functionality implementation pass

- Added SSH socket transport primitives with real TCP connect support and SSH identification exchange.
- Added plaintext and encrypted SSH packet stream readers/writers with partial-read buffering, framing, encryption, MAC verification, and sequence numbers.
- Added curve25519/X25519 KEX primitives and wired curve25519 into `SshSessionStateMachine`; group14 remains fallback.
- Added local TCP proxy/direct-tcpip byte-pump scaffolding with channel abstraction.
- Added DNS domain-to-IP cache with TTL and reverse IP lookup.
- Added TCP-only UDP policy handling and protected SSH endpoint loop-prevention in `TrafficPolicy`.
- Added service-side secret bundle resolution from encrypted storage, without exposing secrets to renderer snapshots.
- Added production guard that rejects insecure secret fallback in production unless `SHADOW_SSH_ALLOW_INSECURE_SECRET_FALLBACK=1`.
- Added local IPC command authorization via `SHADOW_SSH_SERVICE_TOKEN`.
- Added Windows service management scripts: install, uninstall, start, stop.
- Added code signing environment check script.
- Added release/build asset tests for package icons.
- Updated README with service token, Windows service scripts, signing check, socket transport, local proxy, DNS cache, and current remaining limitations.
- Updated Vite/plugin dependencies to remove a high severity `esbuild` audit finding.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.
- Test count is now 10 files / 48 tests.
- No dev or service process was left running.
- Still requiring Windows/real-server implementation or validation: real Windows traffic interception/routing layer, WFP/TUN/route manipulation, process-to-connection attribution, native Windows privileged service binary, named-pipe ACL hardening beyond token auth, installer prompt verification, Windows EXE artifact verification, and live end-to-end SSH/direct-tcpip/shell tests against a controlled server.

### Start: native Windows service and routing implementation scaffolding

- User asked whether only tests remain. Answer: no, real implementation remains.
- No dev/service process should be left running.
- Current focus: add native Windows service/routing scaffolding and contracts that can be validated locally where possible, while clearly separating Windows-only validation that must run on Windows.
- Planned code: native service project layout, Windows service command scripts integration, WFP/TUN/route/process/DNS interface boundaries, service config schema, packaging placeholders for Windows x64/arm64, and tests for generated contracts.

### End: native Windows service and routing implementation scaffolding

- Added a Go native service host under `native/service-go` with no external module dependencies.
- Added native JSON-line service protocol handling with stdio mode, Unix socket mode for macOS/Linux, and Windows named-pipe server code with SDDL ACL allowing LocalSystem, Administrators, and Interactive Users.
- Added service command authorization compatibility through `SHADOW_SSH_SERVICE_TOKEN`.
- Added native routing matcher for proxy-all/selected-rules, domain wildcard rules, IPv4/IPv6 CIDR rules, process-name rules, invalid-rule accounting, and production TCP-only UDP blocking.
- Added platform driver boundaries for routing apply/clear, route manipulation, DNS visibility, process-to-connection attribution, WFP/TUN capability reporting, and future SSH core linkage.
- Added native service app handling for get-status, connect, disconnect, check-tunnel, terminal, update-config, update-routing-rules, and shutdown.
- The native service intentionally fails closed on connect because live SSH/direct-tcpip/shell engine is not linked into that binary yet; it does not claim a connected tunnel without real tunnel support.
- Added Electron `NativeProcessServiceBridge` that starts the matching native binary over `--stdio` when available, consumes responses/events, streams stderr as diagnostics, sends shutdown on app quit, and kills the child if it does not exit quickly.
- Electron still supports explicit `SHADOW_SSH_SERVICE_ENDPOINT` local IPC first; otherwise it starts the native binary if present, and only then falls back to the in-process simulator.
- Added native build/test scripts: `npm run native:test-service` and `npm run native:build-service`.
- Built native service artifacts for `windows/x64`, `windows/arm64`, `macos/x64`, `macos/arm64`, `linux/x64`, and `linux/arm64`.
- Verified artifact formats: Windows PE x64/arm64, macOS Mach-O x64/arm64, Linux ELF x64/arm64.
- Smoke-checked current `native/macos/arm64/shadow-ssh-service --print-capabilities` and `--stdio` shutdown; both exited cleanly.
- Checks passed: `npm run native:test-service`, `npm run native:build-service`, `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`, `npm audit --audit-level=critical`.
- Test count remains 10 TypeScript test files / 48 tests, plus Go native service tests for app/protocol/routing.
- Confirmed no `shadow-ssh-service` process was left running after smoke/build checks.
- Still requiring Windows/real-server implementation or validation: WFP/TUN/route manipulation driver, process-to-connection attribution implementation, live Windows service SCM runtime validation, installer prompt verification, Windows artifact execution/signing verification, and live SSH/direct-tcpip/shell integration tests against a controlled server.

### Start: Windows SCM service entrypoint implementation

- Continuing because not all production service work is just tests.
- No dev/service process should be left running.
- Current focus: add a real Windows Service Control Manager entrypoint to the native service binary using WinAPI/syscall, update install script binPath arguments, and cross-compile Windows artifacts again.

### End: Windows SCM service entrypoint implementation

- Added Windows-only Service Control Manager entrypoint in `native/service-go/internal/windowsservice` using direct WinAPI/syscall calls: `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, and `SetServiceStatus`.
- Added service stop/shutdown handling that moves the service to stop-pending and cancels the native service context.
- Updated Windows named-pipe endpoint handling so blocking pipe connect/read paths close on context cancellation, avoiding service stop hangs when no client is connected.
- Added `--service` flag to the native service binary. In service mode it runs the same local endpoint protocol under SCM control.
- Updated `scripts/install-service.ps1` to install binPath as `shadow-ssh-service.exe --service --endpoint "\\.\pipe\shadow-ssh-service"` unless overridden by environment variables.
- Rebuilt native artifacts for Windows/macOS/Linux x64/arm64 after SCM changes.
- Verified Windows artifact formats again as PE x64 and PE arm64.
- Smoke-checked current macOS/arm64 stdio shutdown after rebuild.
- Checks passed after this pass: `npm run native:test-service`, `npm run native:build-service`, `npm run lint`, `npm run build`.
- Confirmed no `shadow-ssh-service` process was left running.
- Still requiring Windows machine validation: actual SCM install/start/stop behavior, UAC/installer prompt behavior, Windows named-pipe ACL runtime behavior, EXE execution under Windows x64/arm64, and signing/notarization release checks.

## 2026-06-13

### Start: close remaining production-ready implementation gaps

- User asked to close full production-ready gaps and challenged why they remain.
- No dev/service process should be left running.
- Current focus: replace fail-closed native/app service behavior where possible with a real live SSH controller contract, reconnect/session lifecycle, terminal/direct-tcpip command surface, keepalive/dead-session state, and stricter production diagnostics.
- Windows-only WFP/TUN/route manipulation, process-to-connection attribution, SCM runtime checks, UAC prompt checks, and live SSH tests against an external controlled server may still require the proper OS/server environment, but code paths should be explicit and fail closed rather than silently simulating success.

### End: close remaining production-ready implementation gaps

- Added `SshLiveClient` over the custom SSH core with real TCP SSH connection, identification exchange, KEX/NEWKEYS, encrypted packet transport, host-key fingerprint verification, password auth, private-key auth, keepalive, disconnect, direct-tcpip channel opening, direct-tcpip endpoint checks, shell channel open, shell input, terminal output events, PTY resize support, and direct channel close.
- Fixed SSH packet stream sequence numbers so encrypted MAC sequence numbers continue after plaintext KEX/NEWKEYS packets instead of resetting to zero.
- Fixed channel handling for valid remote channel id `0`.
- Added SSH global keepalive request/disconnect encoders and terminal window-change request encoder.
- Added `LiveSshServiceBridge` as the default Electron service path. It connects UI lifecycle to real live SSH instead of simulator/native fail-closed mode.
- Added reconnect loop that preserves the last user connect request and retries until user disconnects.
- `Check tunnel` now uses SSH direct-tcpip through the live SSH client in the default service path.
- Terminal open/input now uses a live SSH shell channel in the default service path.
- Native process service remains available for explicit Windows service-mode testing with `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1`.
- Updated UI transport badge to show `Live SSH`.
- Updated README to describe the default live SSH service path and explicit native service mode.
- Added regression tests for post-NEWKEYS sequence carry-over and remote channel id zero.
- Fixed RSA public-key auth export for OpenSSH compatibility: auth algorithm may be `rsa-sha2-256`/`rsa-sha2-512`, while the RSA key blob remains `ssh-rsa`.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`, `npm run native:test-service`, `npm run native:build-service`, `npm audit --audit-level=critical`.
- Test count is now 10 TypeScript test files / 50 tests, plus Go native service tests for app/protocol/routing/windowsservice package coverage.
- Smoke-checked current macOS/arm64 native service stdio shutdown after rebuild.
- Verified representative native artifact formats after rebuild: Windows PE x64/arm64, macOS Mach-O arm64, Linux ELF arm64.
- Confirmed no `shadow-ssh-service` process was left running.
- Remaining items for user/manual environment validation: real Windows WFP/TUN/route manipulation implementation and behavior, process-to-connection attribution on Windows, Windows SCM install/start/stop on Windows, UAC/installer prompts, Windows EXE execution/signing verification, and live SSH/direct-tcpip/shell acceptance against the user's controlled SSH servers and client matrix.

### Start: Windows process-to-connection attribution implementation

- Continuing production closure for Windows selected process rules.
- No dev/service process should be left running.
- Current focus: implement Windows TCP process attribution in the native service driver using WinAPI/syscall so Windows tests can inspect PID/process names for active TCP connections.

### End: Windows process-to-connection attribution implementation

- Added Windows-only native service TCP process attribution implementation using `GetExtendedTcpTable` for IPv4/IPv6 TCP tables.
- Added PID-to-process-name resolution via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` and `QueryFullProcessImageNameW`.
- Updated Windows native capabilities to report `processConnectionAttribution=true`.
- Checks passed after this change: `npm run native:test-service`, `npm run typecheck`, `npm run test`, `npm run lint`, `npm run build`.
- Attempted `npm run native:build-service` for cross-compiling the Windows artifacts with this final WinAPI file, but the approval was rejected by the environment due to usage/approval limit. This needs to be rerun in the user's environment before Windows binary testing.
- No dev or service process was started or left running in this final pass.

## 2026-06-15

### Start: close final routing/interception gaps

- User asked to close everything remaining and return.
- No dev/service process should be left running.
- Current focus: add a practical production TCP interception path that can be tested on Windows clients without a kernel WFP/TUN driver: local SOCKS5 over live SSH direct-tcpip, Windows system proxy/PAC scripts for proxy-all and selected domain rules, production TCP-only enforcement, and updated docs/tests.

### End: close final routing/interception gaps

- Added production SOCKS5 local proxy over live SSH `direct-tcpip` channels.
- Live SSH service now starts a local SOCKS5 listener after successful SSH auth and stops it on Disconnect/app quit.
- Added Windows user-level system proxy manager:
  - Proxy all sets Windows SOCKS proxy to the local SOCKS5 listener.
  - Selected domain/IP rules generate a PAC file and set `AutoConfigURL`.
  - Previous Windows proxy settings are restored on Disconnect/app quit.
  - WinHTTP proxy is imported from IE/user proxy settings after apply/restore.
- Added PAC generation for enabled domain rules and IPv4 CIDR rules.
- Added production TCP-only path through SOCKS5/system proxy/PAC; UDP remains explicitly unsupported rather than silently proxied.
- Added SOCKS5 handshake parser tests and PAC generation tests.
- Added native service command `list-process-connections` for Windows TCP PID/process attribution checks.
- Rebuilt native service artifacts for Windows/macOS/Linux x64/arm64 after native protocol and Windows attribution changes.
- Smoke-checked native macOS/arm64 stdio shutdown; it exited cleanly.
- Verified native artifact formats: Windows PE x64/arm64, macOS Mach-O x64/arm64, Linux ELF x64/arm64.
- Updated README and native README to describe the final live SSH + SOCKS5 + Windows system proxy/PAC routing path and explicit native service mode.
- Checks passed: `npm run native:test-service`, `npm run native:build-service`, `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`.
- Test count is now 11 TypeScript test files / 52 tests, plus Go native service tests.
- `npm audit --audit-level=critical` could not be completed in this pass because network audit escalation was rejected by policy: it would send dependency metadata to the external npm registry without explicit separate user authorization.
- Confirmed no `shadow-ssh-service` process was left running.

### Start: battery drain and Twitch live streaming fixes

- User reported battery drain and Twitch live streams freezing.
- No dev/service process should be left running.
- Current focus: fix SSH channel flow control for long-running high-throughput streams, reduce unnecessary keepalive/reconnect activity, add idle cleanup for SOCKS/direct-tcpip channels, and add regression tests for streaming/window behavior.

### End: battery drain and Twitch live streaming fixes

- Fixed SSH inbound channel flow control: `SSH_MSG_CHANNEL_DATA` now consumes local window and automatically emits `SSH_MSG_CHANNEL_WINDOW_ADJUST` when the receive window drops below half.
- Increased SSH channel receive window from 1 MiB to 16 MiB and max packet size from 32 KiB to 64 KiB to reduce service packet churn and avoid stalls on high-throughput live video streams.
- Added regression test for streaming data window replenishment; test count is now 11 files / 53 tests.
- Made SSH keepalive traffic-aware: keepalive is skipped when there has been recent SSH activity, so active Twitch/video traffic does not also generate keepalive packets.
- Raised effective minimum keepalive interval to 60 seconds and changed new config default to 120 seconds.
- Added SOCKS5 idle cleanup for inactive local/direct-tcpip connections, defaulting to 5 minutes, with timers unref'd so they do not keep the process awake.
- Increased reconnect backoff ceiling to 5 minutes and added jitter to avoid frequent wakeups while offline.
- Checks passed: `npm run typecheck`, `npm run test`, `npm run lint`, `npm run build`.
- Confirmed no `shadow-ssh-service` process was left running.

### Start: macOS/Linux production packaging support

- User asked to add macOS and Linux production build support after trying `npm run build:prod-`.
- No dev/service process should be left running.
- Current focus: add explicit production package commands for Windows/macOS/Linux/all targets, include native service builds in the packaging pipeline, add macOS `.icns` icon support, and make artifact naming/locations clear for release testing.

### End: macOS/Linux production packaging support

- Added production packaging scripts:
  - `npm run build:prod` / `npm run build:prod-all` for all configured targets.
  - `npm run build:prod-win` / `npm run build:prod-exe` for Windows NSIS x64/arm64.
  - `npm run build:prod-mac` / `npm run build:prod-macos` for macOS DMG+ZIP x64/arm64.
  - `npm run build:prod-linux` for Linux AppImage+DEB x64/arm64.
- Added `package:prepare` so production packaging rebuilds native service binaries for Windows/macOS/Linux x64/arm64 before Electron packaging.
- Added PowerShell and POSIX wrapper scripts for production all/mac/linux builds.
- Added macOS `resources/icons/icon.icns` and reproducible `npm run icons:mac` generator.
- Updated Electron Builder config with platform/arch targets, explicit artifact names, macOS `.icns`, Linux DEB target, and external-only native resources under `process.resourcesPath/native`.
- Excluded `.DS_Store` from git and packaged native resources.
- Updated README with Go 1.23+ production packaging requirement, macOS/Linux/Windows build commands, artifact name examples, and host validation notes.
- Checks passed: `npm run icons:mac`, `npm run typecheck`, `npm run test`, `npm run lint`, `npm run build`, `npm run native:test-service`, `npm run native:build-service`.
- Packaging smoke checks passed: `npx electron-builder --mac --arm64 --dir --publish never` and `npx electron-builder --linux --arm64 --dir --publish never`.
- Verified packaged native resources are present in macOS and Linux unpacked outputs, binary formats match Windows/macOS/Linux arm64, and `.DS_Store` is not included in packaged native resources.
- Confirmed no `shadow-ssh-service` process is running after the checks.

### Start: portable production packaging

- User asked to make portable builds instead of installation flows for Windows and other systems where possible.
- No dev/service process should be left running.
- Current focus: switch default production package commands to portable artifacts, keep installer/package targets behind explicit opt-in scripts, update wrapper scripts/docs, and smoke-check Electron Builder config without launching the app.

### End: portable production packaging

- Switched default production package commands to portable-first outputs:
  - `npm run build:prod` / `npm run build:portable` build all portable targets.
  - `npm run build:prod-win` / `npm run build:portable-win` build Windows portable EXE+ZIP.
  - `npm run build:prod-mac` / `npm run build:portable-mac` build macOS portable ZIP.
  - `npm run build:prod-linux` / `npm run build:portable-linux` build Linux AppImage+tar.gz.
- Kept installable outputs as explicit opt-in only: `build:installer-win`, `build:package-mac`, and `build:package-linux`.
- Updated Electron Builder targets/artifact names for portable Windows/macOS/Linux outputs and installer/package artifact names.
- Added PowerShell and POSIX `scripts/build-portable-*` wrappers.
- Added Linux `desktopName` metadata and `linux.syncDesktopName=true` for better AppImage/desktop window association.
- Hardened native Go scripts to use project-local `.cache/go-build` and ignore stale inherited `GOROOT/GOTOOLDIR`; this fixed a local Go 1.26.2 binary plus Go 1.25.3 GOROOT mismatch.
- Updated README build instructions and artifact examples to document portable as the default production path.
- Checks passed: package JSON parse, `npm run typecheck`, `npm run test`, `npm run lint`, `npm run build`, `npm run native:test-service`, `npm run native:build-service`.
- Portable smoke artifacts built on the current macOS host:
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-macos-portable-arm64.zip`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.tar.gz`
- Verified packaged native resources are present in Windows/macOS/Linux unpacked outputs and `.DS_Store` is not included.

### Start: runnable-only portable artifacts

- User asked to avoid installer/archive leftovers such as `*.nsis.7z` and prefer direct runnable artifacts for every platform/architecture.
- No dev/service process should be left running.
- Current focus: make default portable outputs runnable-only: Windows portable `.exe`, Linux `.AppImage`, and macOS unpacked `.app` directories; keep archive/package outputs only behind explicit opt-in commands.

### End: runnable-only portable artifacts

- Removed archive targets from default portable builds:
  - Windows portable now builds per-arch `.exe` only.
  - macOS portable now builds unpacked `.app` bundles via `dir` target instead of ZIP.
  - Linux portable now builds `.AppImage` only instead of AppImage+tar.gz.
- Updated `build:portable` to clean `release/` before building all runnable artifacts, preventing stale ZIP/tar/DMG/DEB/NSIS artifacts from remaining in the default release output.
- Split Windows portable x64 and arm64 into separate Electron Builder invocations so the default all-platform build does not emit an extra generic `windows-portable.exe`.
- Updated README artifact examples to match the final runnable-only outputs, including Linux `x86_64` AppImage naming.
- Full `npm run build:portable` passed after the changes.
- Verified final `release/` contains no `*.nsis.7z`, `*.zip`, `*.tar.gz`, `*.7z`, `*.dmg`, or `*.deb`.
- Final runnable artifacts produced:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
- Verified Windows unpacked app/native service binaries match x64/arm64 and packaged native resources do not include `.DS_Store`.

### Start: Windows portable starts without UI

- User reported `shadow-ssh-0.1.0-windows-portable-x64.exe` starts but no UI appears.
- No dev/service process should be left running.
- Current focus: inspect packaged Electron main/renderer loading paths, add production diagnostics for renderer/window failures, and verify the packaged macOS smoke path where possible from this host.

### End: Windows portable starts without UI

- Found two startup/UI resilience gaps:
  - Renderer `api.ts` threw during module import when the preload API was missing, which could leave a completely blank renderer instead of a visible error UI.
  - Electron main created the BrowserWindow only after storage/service startup, so a startup error before `createWindow()` could leave the process running with no visible UI.
- Changed renderer API fallback so missing preload no longer crashes React startup; it now renders a default snapshot with a visible Diagnostics error.
- Reworked Electron main bootstrap:
  - Creates the BrowserWindow and registers IPC before async storage/service initialization.
  - Uses a startup placeholder service until the real live SSH service is ready.
  - Logs main-process startup, renderer load, preload, render-process, uncaught exception, and unhandled rejection failures to `logs/main.log` under Electron `userData`.
  - Broadcasts startup failures into UI Diagnostics instead of failing silently.
- Fixed packaged icon path to use the renderer icon inside the packaged app instead of `process.resourcesPath/icon.svg`.
- Checks passed: `npm run typecheck`, `npm run test`, `npm run lint`, `npm run build`.
- Rebuilt full portable release with `npm run build:portable`; the Windows x64 artifact to retest is `release/shadow-ssh-0.1.0-windows-portable-x64.exe`.
- Verified Windows `app.asar` includes updated `dist/main/main.js`, `dist/preload/preload.js`, `dist/renderer/index.html`, and the new renderer bundle.
- Verified final `release/` still has no archive/installable artifacts and no relevant build/app/service process is running.

### Start: Windows portable creates no userData/log directory

- User reported `dir "$env:APPDATA\Shadow SSH" -Recurse` finds nothing after launching the Windows portable x64 build, and `AppData\Roaming` is empty.
- No dev/service process should be left running.
- Current focus: add earlier main-process logging before `app.whenReady()`, force an explicit Windows-friendly `userData` path, and verify packaged startup behavior as far as possible from the current macOS host.
- Added a packaged CommonJS bootstrap plan so Electron loads a minimal crash-logging entrypoint before the ESM application module. This should produce logs under `%APPDATA%\Shadow SSH\logs\main.log` or `%TEMP%\Shadow SSH\logs\main.log` even when the main module fails during import.

### End: Windows portable creates no userData/log directory

- Added `src/main/bootstrap.cts` as the packaged Electron entrypoint. It writes synchronous startup/crash logs before importing the ESM main application module and shows a minimal fatal-startup window if that import fails.
- Changed `package.json` `main` to `dist/main/bootstrap.cjs` and updated the dev `wait-on` script so local Electron startup waits for both bootstrap and main output.
- Updated `tsconfig.node.json` to include `.cts` files, preventing builds from silently omitting the bootstrap entrypoint.
- Kept the explicit `userData` path in `src/main/main.ts` and added a fallback log mirror under the OS temp directory:
  - Windows primary: `%APPDATA%\Shadow SSH\logs\main.log`
  - Windows fallback: `%TEMP%\Shadow SSH\logs\main.log`
- Checks passed with the new bootstrap included: `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`.
- Full production portable release rebuilt successfully with `npm run build:portable` after allowing electron-builder network access.
- Verified every packaged `app.asar` uses `dist/main/bootstrap.cjs` and includes `dist/main/bootstrap.cjs`, `dist/main/main.js`, and renderer output:
  - `release/win-unpacked/resources/app.asar`
  - `release/win-arm64-unpacked/resources/app.asar`
  - `release/mac/Shadow SSH.app/Contents/Resources/app.asar`
  - `release/mac-arm64/Shadow SSH.app/Contents/Resources/app.asar`
  - `release/linux-unpacked/resources/app.asar`
  - `release/linux-arm64-unpacked/resources/app.asar`
- Current release artifacts:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified no matching `electron-builder`, `Shadow SSH`, `shadow-ssh-service`, `vite`, or `tsc` process remains running after the build.

### Start: Windows portable white renderer

- User provided Windows `main.log` showing bootstrap, main, app ready, BrowserWindow creation, storage init, and services init all succeed, but the window remains white.
- Found the likely renderer packaging bug: `dist/renderer/index.html` uses absolute Vite asset URLs (`/assets/...`) which do not resolve correctly under packaged Electron `file://` loading from `app.asar`.
- Current focus: switch Vite production assets to relative URLs, add renderer console/load diagnostics to `main.log`, rebuild portable artifacts, and verify packaged `index.html` references relative assets.

### End: Windows portable white renderer

- Fixed the white renderer root cause by setting Vite `base: "./"` in `vite.config.ts`, so packaged renderer HTML now loads `./assets/...` and `./icon.svg` correctly from `app.asar/dist/renderer`.
- Added Electron main diagnostics for renderer `did-finish-load`, renderer console messages, and a delayed React root mount check. If the renderer is blank again, `main.log` should include `Renderer mount status` and any console errors.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`.
- Rebuilt full portable release with `npm run build:portable`.
- Verified Windows packaged `app.asar` for both x64 and arm64:
  - `package.json` main is `dist/main/bootstrap.cjs`.
  - `dist/renderer/index.html` references `href="./icon.svg"`, `src="./assets/index-B9TNvLlr.js"`, and `href="./assets/index-NSSN9ps7.css"`.
  - The referenced JS, CSS, and icon files exist inside `app.asar`.
- Current Windows artifacts to retest:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
- Verified no matching `electron-builder`, `Shadow SSH`, `shadow-ssh-service`, `vite`, or `tsc` process remains running after the rebuild.

### Start: logs tab and manual logging controls

- User reported live SSH reconnect/auth failure: `SSH authentication failed: error:0900006e:PEM routines:OPENSSL_internal:NO_START_LINE`.
- User requested a dedicated logs tab with manual enable/disable controls.
- Current focus: persist logging settings, expose log paths and clear-log action through IPC, add a Logs tab in the sidebar, and gate runtime diagnostics/file logging according to user-controlled settings.
- User also reported that the main/sidebar application icon is missing after launch.

### End: logs tab and manual logging controls

- Added persisted logging settings:
  - `diagnosticsLoggingEnabled` controls in-app runtime diagnostics collection.
  - `fileLoggingEnabled` controls main-process file logging after settings are loaded.
- Added IPC and preload methods to clear runtime diagnostics, read the main log file, and clear the main log file.
- Added a dedicated `Logs` sidebar tab with:
  - Runtime diagnostics/file logging toggles.
  - Log path display.
  - Runtime diagnostics list with copy/clear.
  - Main log file view with refresh/copy-all/clear-file.
- Fixed the missing sidebar app icon by changing the renderer image path from absolute `/icon.svg` to relative `./icon.svg`.
- Improved SSH private-key handling:
  - Saving a key now rejects public-key text, empty text, file paths, and other non-private-key content before storing it.
  - `loadPrivateKey` now wraps OpenSSL parse errors in an actionable message instead of surfacing raw `NO_START_LINE`.
  - Live SSH no longer schedules reconnect for non-retryable auth/config errors such as authentication failure, missing secrets, host-key errors, or invalid private-key input.
- Checks passed: `npm run typecheck`, `npm run lint`, `npm run test` (54 tests), `npm run build`.
- The normal `npm run build:portable` path was blocked by sandbox network/usage limits when electron-builder attempted GitHub access after cleaning `release/`.
- Restored release artifacts using cached local Electron distributions through `--config.electronDist=...`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified every packaged `app.asar` uses `dist/main/bootstrap.cjs`, references relative renderer assets, contains `dist/renderer/icon.svg`, and includes the Logs tab bundle text.
- Could not run final `pgrep` process verification because both sandboxed and escalated process-list reads are blocked in the current environment. All build tool sessions started during this work have exited.

### Start: menu, transparent icon, log path cleanup, connect log polish

- User provided copied runtime/file logs from a Windows connect attempt. The auth failure is now non-retrying, but the displayed message still includes raw OpenSSL `NO_START_LINE`.
- User reported Windows desktop/app icon has a white square background and should be transparent.
- User reported the default Electron menu bar (`File Edit View Window`) is visible and wants a unified app-only window.
- User reported fallback log paths contain Windows short-name `ADMINI~1`; requested dynamic full user path instead.
- Current focus: hide the Electron application menu, regenerate package icons with alpha transparency, derive fallback log path from `%LOCALAPPDATA%`/`%USERPROFILE%` instead of `os.tmpdir()` on Windows, and remove raw OpenSSL details from connect diagnostics.

### End: menu, transparent icon, log path cleanup, connect log polish

- Removed the default Electron application menu in packaged/dev main process via `Menu.setApplicationMenu(null)` and `autoHideMenuBar: true`.
- Changed Windows fallback log path resolution to prefer `%LOCALAPPDATA%\Temp\Shadow SSH\logs\main.log`, then `%USERPROFILE%\AppData\Local\Temp\...`; this avoids `os.tmpdir()` short-name paths such as `ADMINI~1` in app diagnostics.
- Regenerated package icons with a transparent edge background:
  - `resources/icons/icon.png`
  - `resources/icons/icon.ico`
  - `resources/icons/icon.icns`
- Added `npm run icons:transparent` and a PNG transparency test so icon alpha survives future icon regeneration.
- Simplified private-key parse failure text so runtime diagnostics no longer expose raw OpenSSL `NO_START_LINE` internals.
- Reduced portable package weight:
  - Electron locales are limited to `en-US`.
  - Platform packages now include only the native service for the current platform/architecture.
  - React, React DOM, and lucide-react were moved to devDependencies so Vite-bundled renderer packages are not copied into `app.asar`.
- Size results after rebuild:
  - Windows x64 portable: `91M` -> `80M`.
  - Windows arm64 portable: `84M` -> `73M`.
  - Linux x64 AppImage: `130M` -> `85M`.
  - Linux arm64 AppImage: `128M` -> `78M`.
  - Windows x64 `app.asar`: `26M` -> `396K`.
- Checks passed: `npm run lint`, `npm run typecheck` through `npm run package:prepare`, `npm run test`, `npm run package:prepare`.
- Rebuilt portable/release artifacts using cached local Electron distributions through `--config.electronDist=...`:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified packaged artifacts contain no runtime `node_modules`, contain `dist/main/bootstrap.cjs` and `dist/renderer/index.html`, keep only `en-US.pak` on Windows/Linux, and include only the target-arch native service in each release output.

### Start: private-key parse diagnostics and file logs

- User reported `SSH authentication failed: Unable to load SSH private key. Check the key format and passphrase.` while the key is believed to be valid.
- User also reported that the Logs tab / file logs do not contain enough detail for the connect failure.
- Current focus: add safe private-key parse diagnostics without logging key/passphrase material, normalize escaped newline key input, and ensure service diagnostics are mirrored into the main log file.

### End: private-key parse diagnostics and file logs

- Added private-key text normalization before validation/parsing:
  - Strips BOM and outer whitespace.
  - Converts one-line keys containing literal `\n` / `\r\n` escapes into real newlines.
  - Normalizes CRLF/CR line endings to LF before `crypto.createPrivateKey`.
- Added a built-in unencrypted OpenSSH private-key parser for common `openssh-key-v1` keys:
  - `ssh-ed25519`
  - `ssh-rsa`
  - `ecdsa-sha2-nistp256`
  - `ecdsa-sha2-nistp384`
  - `ecdsa-sha2-nistp521`
- Encrypted OpenSSH keys now produce explicit safe diagnostics with `openSshCipher`/`openSshKdf`; passphrase-protected PEM/PKCS8 remains handled by Node/OpenSSL.
- Verified the parser against real temporary `ssh-keygen` keys: `id_ed25519`, `id_rsa`, and `id_ecdsa`.
- App storage now saves normalized private-key text and fingerprints the normalized form, so newly saved keys do not keep escaped newline artifacts.
- Added `SshPrivateKeyLoadError` and `SshAuthenticationError` diagnostics plumbing.
- On private-key parse failure, service diagnostics now include safe metadata only:
  - key format/header/footer labels,
  - original/normalized char and line counts,
  - line ending style,
  - escaped-newline/BOM/passphrase-present/encrypted/header-footer-match flags,
  - parser error text.
- Main process now mirrors service `diagnostics-appended` and service `error` events into `main.log`, so connect failures are visible in the file log even when the Logs tab was not open.
- Added tests for escaped-newline private keys, unencrypted OpenSSH Ed25519 keys, and safe parse diagnostics.
- Checks passed: `npm run typecheck`, `npm run lint`, focused `npx vitest run tests/ssh-transport-security.test.ts`, full `npm run test` (58 tests), and `npm run package:prepare`.
- Rebuilt portable/release artifacts using cached local Electron distributions:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified every packaged `app.asar` contains the new private-key diagnostics, escaped-newline normalization, OpenSSH parser code, has no runtime `node_modules`, and keeps only target-arch native service resources.

### Start: single file log and connect auth diagnostics

- User reported that pressing Connect appends runtime diagnostics but does not append anything to the file log.
- User requested a single log file only, without the secondary temp log path.
- User still sees `SSH authentication failed: Unable to load SSH private key. Check the key format and passphrase.` when connecting.
- Current focus: write service connect/auth diagnostics to the primary `AppData/Roaming` main log, remove temp fallback log output/path display, and make private-key parse diagnostics more actionable for the remaining auth failure.

### End: single file log and connect auth diagnostics

- Removed the secondary temp fallback log path from bootstrap and main process logging. The app now writes/reads/clears only the primary log under the explicit user data directory, e.g. `%APPDATA%\Shadow SSH\logs\main.log` on Windows.
- Removed `fallbackLog=...Temp...` from startup log lines.
- Service diagnostics and service error events are now mirrored to `main.log` with `force: true`, so Connect/auth failures are written even if ordinary file logging was disabled in settings.
- Added an explicit live SSH `Connect requested ...` diagnostic with host, port, auth type, routing mode, and boolean key/passphrase presence, without logging secrets.
- Improved private-key failure messaging for encrypted OpenSSH keys: they now produce a direct `Encrypted OpenSSH private keys are not supported yet...` error instead of the generic format/passphrase message.
- Added a regression test for encrypted OpenSSH diagnostics.
- Checks passed: `npm run typecheck`, `npm run lint`, focused `npx vitest run tests/ssh-transport-security.test.ts`, full `npm run test` (59 tests), and `npm run package:prepare`.
- Rebuilt portable/release artifacts using cached local Electron distributions:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified every packaged `app.asar` has single-log behavior, forced service diagnostic file logging, the live SSH connect-request diagnostic, and the encrypted OpenSSH error message.

### Start: Windows icon white background regression

- User reported the application icon again appears with a white background.
- Current `resources/icons/icon.png` has transparent corners, but `resources/icons/icon.ico` is a single PNG-in-ICO entry, which can render with a white background in some Windows shell/portable EXE contexts.
- Current focus: generate a multi-resolution Windows ICO with uncompressed 32-bit DIB entries and alpha masks, then rebuild Windows portable artifacts.

### End: Windows icon white background regression

- Reworked `scripts/ensure-transparent-icons.mjs`:
  - Fully transparent pixels now have RGB cleared to `0,0,0` instead of keeping hidden white RGB.
  - Windows `icon.ico` is now generated as a 7-size 32-bit DIB ICO with alpha and AND masks: 256, 128, 64, 48, 32, 24, and 16 px.
  - The ICO is no longer a single PNG-in-ICO entry, which avoids Windows shell contexts that render PNG icon entries with a white background.
- Regenerated:
  - `resources/icons/icon.png`
  - `resources/icons/icon.ico`
  - `resources/icons/icon.icns`
- Added build asset tests for PNG corner RGBA `[0,0,0,0]` and multi-size non-PNG ICO entries.
- Updated `resources/icons/README.md` with the Windows ICO format requirement.
- Checks passed: `npm run lint`, `npm run typecheck`, `npm run test` (60 tests).
- Rebuilt portable/release artifacts using cached local Electron distributions:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified packaged `app.asar` outputs still contain the renderer icon, bootstrap entrypoint, no runtime `node_modules`, single target-arch native service resources, and only `en-US.pak` locales.

### Start: check tunnel channel lifecycle

- User provided logs where pressing Check tunnel causes `ERROR Unknown channel 0.` twice and then reconnects.
- The log pattern points to a late SSH channel message arriving after the check-tunnel direct-tcpip channel has already been closed locally.
- Current focus: make late per-channel messages for already-closed channels non-fatal, keep the SSH transport alive, and verify Check tunnel reports success/failure without triggering reconnect.

### End: check tunnel channel lifecycle

- Fixed `SshSessionStateMachine.receiveChannelMessage` so late `WINDOW_ADJUST`, `DATA`, `EOF`, `CLOSE`, `SUCCESS`, and `FAILURE` messages for an already-closed local channel return an `ignored` channel event instead of throwing `Unknown channel N`.
- Kept channel open confirmation/failure strict; unexpected open lifecycle still surfaces as an error.
- Cleaned up direct-tcpip channel emitters immediately on local close, preventing emitter leaks now that late server close/eof messages are ignored.
- Added Check tunnel diagnostics:
  - `Tunnel check requested for ...`
  - `SSH direct-tcpip check succeeded for ...`
  - `Tunnel check failed for ...`
  - skipped check when SSH is disconnected.
- Added regression coverage for the check-tunnel lifecycle: direct-tcpip open, local close, then late server channel messages on channel `0` are ignored and do not throw.
- Checks passed: focused `npx vitest run tests/ssh-session-state.test.ts`, `npm run typecheck`, `npm run lint`, full `npm run test` (61 tests), and `npm run package:prepare`.
- Rebuilt portable/release artifacts using cached local Electron distributions:
  - `release/shadow-ssh-0.1.0-windows-portable-x64.exe`
  - `release/shadow-ssh-0.1.0-windows-portable-arm64.exe`
  - `release/shadow-ssh-0.1.0-linux-portable-x86_64.AppImage`
  - `release/shadow-ssh-0.1.0-linux-portable-arm64.AppImage`
  - `release/mac/Shadow SSH.app`
  - `release/mac-arm64/Shadow SSH.app`
- Verified every packaged `app.asar` contains ignored-channel handling, direct-channel emitter cleanup, Check tunnel diagnostics, no runtime `node_modules`, target-arch native service resources, and only `en-US.pak` locales.
