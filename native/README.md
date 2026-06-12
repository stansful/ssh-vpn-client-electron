# Native service layout

Electron must not own low-level routing. Native privileged service binaries are expected at:

```text
native/
  windows/
    x64/shadow-ssh-service.exe
    arm64/shadow-ssh-service.exe
  macos/
    x64/shadow-ssh-service
    arm64/shadow-ssh-service
  linux/
    x64/shadow-ssh-service
    arm64/shadow-ssh-service
```

The Electron main process resolves the active platform and architecture through `src/main/platform/targets.ts`.
When a binary is missing, the app uses the development simulator transport. The simulator exercises UI, storage,
IPC, diagnostics, terminal plumbing, and routing-rule validation, but it does not create an SSH tunnel or OS routes.

Future service contract:

- local-only IPC endpoint;
- commands: connect, disconnect, status, update config, update routing rules, check tunnel, open terminal, terminal input;
- events: status changed, diagnostics appended, tunnel check result, terminal output, error;
- privileged routing/core implementation per platform;
- reusable custom SSH core shared by platform-specific service shells.

Development IPC simulator:

```powershell
npm run service:simulator
```

Then start Electron with `SHADOW_SSH_SERVICE_ENDPOINT` pointing to that endpoint. If the endpoint is not available,
Electron falls back to the in-process simulator and records a startup diagnostic warning.

Native service host:

```powershell
npm run native:test-service
npm run native:build-service
```

The Go service host builds without external modules for:

- `windows/x64` and `windows/arm64`
- `macos/x64` and `macos/arm64`
- `linux/x64` and `linux/arm64`

Electron starts the matching native binary over `--stdio` when it is present and no
`SHADOW_SSH_SERVICE_ENDPOINT` is configured. The process bridge sends `shutdown` and kills the child on app quit if it
does not exit quickly, so local runs do not leave a service process hanging.

The native host intentionally fails closed for `connect` until the live SSH engine and platform routing drivers are
linked into that binary. It does not report a connected tunnel without real SSH/direct-tcpip/shell support.
