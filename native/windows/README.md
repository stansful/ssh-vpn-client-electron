# Windows native payload

Everything in `native/windows/<arch>/` is copied verbatim into the packaged app
(`build.win.extraResources` in `package.json`), including the portable artifact.

## `shadow-ssh-service.exe`

Built by `npm run native:build-service` (run `go mod download` in
`native/service-go` first - the TUN dataplane pulls in a userspace network
stack). Hosts per-connection process attribution and the TUN dataplane.

A quick smoke test without Windows, if Wine is available:

```bash
wine64 native/windows/x64/shadow-ssh-service.exe --print-capabilities
```

It should print one line of JSON. Anything else - in particular a Go panic from
`init()` - means the binary cannot start at all, and neither attribution nor TUN
will work no matter what the app does.

## `wintun.dll` (required for TUN mode only)

Download the signed release from <https://www.wintun.net/> and place the DLL for
the matching architecture next to the service binary:

```
native/windows/x64/wintun.dll
native/windows/arm64/wintun.dll
```

It has to sit in that exact directory: the service loads it by bare name, so the
Windows loader resolves it from the directory of `shadow-ssh-service.exe`. No
`package.json` change is needed - the folder is already packaged wholesale.

The DLL is deliberately not committed: it is a third-party signed binary and
should be fetched from its vendor rather than vendored here.

Without it the service still runs; only TUN mode is unavailable, and the app
falls back to the system-proxy path with a diagnostic saying so.

## Administrator rights

Creating the adapter and editing the routing table require elevation. This
project ships a portable executable only, so there is no installer or Windows
service to hold those rights: **the portable `.exe` has to be started as
administrator for TUN mode to come up.** Started normally it keeps working, with
the system-proxy path and its TCP-only limits.
