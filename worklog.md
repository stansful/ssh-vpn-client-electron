# Worklog

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
