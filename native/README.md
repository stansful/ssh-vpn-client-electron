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
By default Electron uses the built-in live SSH service. Set `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1` to force Electron
to start the matching native binary over `--stdio`.

Service contract:

- local-only IPC endpoint;
- commands: connect, disconnect, status, update config, update routing rules, check tunnel, open terminal, terminal input, list process connections;
- events: status changed, diagnostics appended, tunnel check result, terminal output, error;
- privileged routing/core implementation per platform;
- reusable custom SSH core shared by platform-specific service shells.

Development IPC simulator:

```powershell
npm run service:simulator
```

Then start Electron with `SHADOW_SSH_SERVICE_ENDPOINT` pointing to that endpoint. If the endpoint is not available,
Electron falls back to the built-in live SSH service and records a startup diagnostic warning.

Native service host:

```powershell
npm run native:test-service
npm run native:build-service
```

The Go service host builds without external modules for:

- `windows/x64` and `windows/arm64`
- `macos/x64` and `macos/arm64`
- `linux/x64` and `linux/arm64`

Electron starts the matching native binary over `--stdio` when `SHADOW_SSH_USE_NATIVE_PROCESS_SERVICE=1` is set and no
`SHADOW_SSH_SERVICE_ENDPOINT` is configured. The process bridge sends `shutdown` and kills the child on app quit if it
does not exit quickly, so local runs do not leave a service process hanging.

The native host includes Windows SCM service mode, named-pipe ACLs, routing capability contracts, and Windows TCP
process-to-connection attribution. The default live SSH tunnel path is implemented in Electron main.
