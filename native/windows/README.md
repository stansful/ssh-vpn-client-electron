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

```bash
npm run wintun:download
```

That fetches the signed release from <https://www.wintun.net/>, verifies it
against `scripts/wintun-checksums.json` and installs both architectures:

```
native/windows/x64/wintun.dll
native/windows/arm64/wintun.dll
```

A version with no recorded checksum is downloaded but **not** installed: the
script prints the SHA-256 it saw and stops, so a third-party binary is never
installed unverified. Compare it against the vendor's published value, then
record it with `npm run wintun:download -- --trust-download` and commit the
result, so every later build is checked against it.

No `package.json` change is needed; the folder is packaged wholesale. Windows
packaging refuses to run without the DLL (`scripts/electron-builder-with-local-dist.mjs`),
`npm run wintun:ensure` checks it on demand, and `npm run verify:prod-artifacts`
confirms it reached the built bundle. It used to be only a console warning
during the native build, which is how releases shipped without it.

**After packaging** - the portable build unpacks itself into a fresh
`%TEMP%\<random>\resources\...` folder at every launch and deletes it on exit,
so **nobody can add the DLL to a built portable app's resources**. The helper is
therefore also pointed at folders a person can actually use, in order:

1. beside the service binary (where a packaged copy lands),
2. beside the executable the user launched (`PORTABLE_EXECUTABLE_DIR`),
3. the application data folder, next to the logs.

The Electron side passes 2 and 3 in `SHADOW_SSH_WINTUN_DIRS`. A failure lists
every path that was tried.

The DLL is deliberately not committed: it is a third-party signed binary and
should be fetched from its vendor rather than vendored here.

Without it the service still runs; only TUN mode is unavailable, and the app
falls back to the system-proxy path with a diagnostic saying so - naming the
absolute directory it searched, so a DLL in the wrong folder is obvious.

## Administrator rights

Creating the adapter and editing the routing table require elevation. This
project ships a portable executable only, so there is no installer or Windows
service to hold those rights: **the portable `.exe` has to be started with "Run
as administrator" for TUN mode to come up.** Being signed in as an administrator
is not enough - with UAC on, the process still gets a filtered token. Started
normally it keeps working, with the system-proxy path and its TCP-only limits.

The two prerequisites are reported separately. `--print-capabilities` carries
`tunUnavailableReason`, and the app repeats it verbatim in Diagnostics, so
"missing DLL" and "not elevated" are never confused for one another.
