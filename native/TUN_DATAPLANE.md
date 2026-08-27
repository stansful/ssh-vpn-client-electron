# TUN dataplane plan

## Why

The current interception path is the Windows user proxy (`AutoConfigURL` / `ProxyServer`)
plus a local listener. That setting is advisory and TCP-only: an application has to read it
and choose to obey it. Three classes of traffic therefore never reach us, and no amount of
work on the existing path can capture them:

- **UDP/QUIC.** Chrome and Edge reach Google/YouTube over QUIC by default; Discord voice is
  UDP. The Windows proxy setting has no UDP concept at all.
- **Applications with their own proxy stack or raw sockets.** They simply ignore the setting.
- **Anything that resolves and connects without consulting WinINet/Chromium proxy config.**

Capturing those requires interception below the application, on the network path. That is a
TUN adapter: a virtual interface that owns the routes, so the OS hands us the packets
regardless of what the application intended.

The `platform.Driver` interface already reserves `tunDevice`, `wfpInterception` and
`routeManipulation` capability flags. They stay `false` until the pipeline below is complete;
nothing in the app may branch on a half-built dataplane.

## What each transport can actually carry

This constrains the design and must be settled before writing the forwarding layer.

| Transport | TCP | UDP |
| --- | --- | --- |
| Xray (SOCKS5 inbound) | yes | yes, via `UDP ASSOCIATE` — requires `udp: true` on the inbound, which `buildXrayConfig` currently disables |
| Live SSH | yes, via `direct-tcpip` | **no** — the SSH connection protocol has no datagram channel |

So "all of an application's traffic" is only literally achievable on Xray. On SSH the honest
options for UDP are to drop it (forcing QUIC clients to fall back to TCP, which we do capture)
or to let it pass directly. Dropping is the correct default for a selected process: letting it
pass would leak exactly the traffic the rule was meant to capture. This must be surfaced in
the UI rather than decided silently.

## Layers

All six are implemented. What each one ended up doing, and where:

1. **Adapter** — `internal/tun/adapter_windows.go`. Loads `wintun.dll` by bare name, creates
   the adapter, runs a packet session. `tun.Available()` resolves the DLL without creating an
   adapter, so capability reporting can tell "no DLL" apart from "no privileges".
2. **Routing and kill-switch** — `internal/winroute`. **Nothing existing is modified.** The
   capture is `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`) on the adapter, which beat
   the machine's default route on prefix length alone; the default route is never touched, so
   recovery is only ever deleting routes this process added and there is no window without a
   default route. Every operation carries its own undo command and is journalled to disk
   *before* it is applied, so a hard kill is undone by the next run
   (`Manager.Recover`) — the same discipline `WindowsSystemProxyManager` uses for registry
   state. Changes are made through `netsh ... store=active`: slower than `iphlpapi`, but the
   structs that API needs are union-bearing and cannot be validated without a Windows machine.
3. **Userspace network stack** — `internal/dataplane/stack.go`, on
   `github.com/sagernet/gvisor` (the sing-box fork; upstream `gvisor.dev/gvisor` is the same
   code but its vanity import path resolves through a host that is not always reachable, and
   the fork is the one actually exercised on Windows). A `channel.Endpoint` bridges the
   adapter to the stack; the NIC runs promiscuous and spoofing so it can terminate flows to
   every destination.
4. **Attribution and policy** — `internal/dataplane/attribution.go` and `policy.go`.
   `GetExtendedTcpTable` **and** `GetExtendedUdpTable` (a UDP socket appears in neither the TCP
   table nor anywhere else), with the toolhelp fallback for elevated processes. One snapshot
   serves a burst of flows; a miss - which is what a socket newer than the snapshot looks like -
   forces exactly one refresh. The rule order mirrors `LocalRoutingEnforcer.decide` in
   `src/service/local-routing-enforcement.ts` line for line: protected endpoint, then process
   rule, then domain/IP, then proxy list, then direct list. `policy_test.go` pins each step.
5. **Forwarding** — matched TCP and UDP go to a loopback SOCKS5 inbound
   (`internal/dataplane/socks5.go`); unmatched flows are dialled through
   `internal/winnet`'s interface-pinned dialer. The pinning is not an optimisation: with the
   capture routes up, an ordinary socket opened by the helper would be routed into the adapter
   and arrive back in its own stack. `IP_UNICAST_IF` is the only way out.
6. **DNS** — `internal/dataplane/dns.go`. Queries are forwarded to whatever resolver the
   machine was already using, out through the physical interface, and the answers are parsed
   to learn which name produced which address so domain rules and the curated lists still
   match a flow that only carries an IP. DNS is handled *before* the UDP drop rule, or a
   selected application on the SSH transport would lose name resolution entirely.

Not covered: ICMP is not terminated, so pings to a captured destination do not answer.

## Which transport gets what

| | TCP | UDP | Where the helper sends it |
| --- | --- | --- | --- |
| Xray | tunnelled | tunnelled via `UDP ASSOCIATE` | Xray's own SOCKS inbound, directly |
| Live SSH | tunnelled | **dropped** for a selected process | the Electron process's loopback SOCKS5 listener |

On the SSH transport the local listener is left in place but stops enforcing policy: the
helper has already decided, and a second pass would apply the rules twice with different
information. Everything the listener receives is tunnelled.

## Permissions and packaging

This project ships a portable executable only, so there is no installer or Windows service to
carry privileges:

- Creating the adapter and editing the routing table require administrator rights. With no
  installer, the portable `.exe` has to be started as administrator for TUN mode to come up.
  Started normally it keeps working on the system-proxy path with its TCP-only limits, so the
  driver must report `tunDevice: false` when it is not elevated rather than failing obscurely
  at connect time.
- `wintun.dll` is a signed WireGuard component. It goes next to the service binary in
  `native/windows/<arch>/`, which is already packaged wholesale, so no `package.json` change is
  needed. See `native/windows/README.md`.
- `go.mod` currently has no dependencies. Layer 3 adds gVisor, which is substantial. Vendoring
  and licence review happen on a machine with a Go toolchain.

## UDP policy

Because SSH cannot carry datagrams, "route everything from this process" means something
different per transport, and the difference is visible in the Routing view rather than decided
silently:

- **Xray** — UDP is forwarded through `UDP ASSOCIATE`. The SOCKS inbound now enables it
  (`buildXrayConfig`).
- **SSH** — UDP cannot be tunnelled. For a selected process it is dropped, which makes QUIC
  clients fall back to TCP, which *is* tunnelled. Letting it out directly would leak exactly
  the traffic the rule exists to capture.

The drop-versus-direct choice becomes a setting when the dataplane lands; until then the
Routing view states the limitation instead of offering a control that cannot do anything.

## The helper never started, and that was the original bug

`internal/windowsservice` built its two service callbacks in package-level variables, and
`serviceMain` returned nothing. `syscall.NewCallback` requires exactly one uintptr-sized
result, so the helper panicked in `init()` - before `main()` - on **every** launch, exit code
2, including the `--stdio` launches that never touch service mode:

```
panic: compileCallback: expected function with one uintptr-sized result
shadowssh/service/internal/windowsservice.init()
```

That signature has been wrong since the first commit, so the native helper has never run on
Windows. Process attribution therefore always reported unavailable,
`LocalRoutingEnforcer.isEnforceable` always returned false, and every connection fell through
to the PAC-learning path - which is why a `process.name` rule looked inert long before TUN
existed. The fix is `serviceMain` returning `uintptr`, the callbacks built lazily so
service-mode code can never take down a process that is not a service, and compile-time
assertions on both signatures.

## Turning it on

The dataplane falls back rather than failing:

1. Put `wintun.dll` in `native/windows/<arch>/` (see `native/windows/README.md`).
2. Start the portable `.exe` **as administrator**. Without elevation the helper reports
   `tunDevice: false` and the app stays on the system-proxy path, saying so in diagnostics.
3. *Capture traffic with a tunnel adapter (TUN)* lives with the process rules in the Routing
   view (`AppSettings.tunDataplaneEnabled`) and is on by default. Store schema 2 turns it on
   once for stores written by the build where the setting could not work.

`LiveSshServiceBridge.applyTunRouting` and `XrayServiceBridge.applyTunRouting` try the adapter
first on every routing apply and return `false`, having changed nothing, whenever it cannot be
used.

## Turning the tunnel off and on again

Reconnecting destroys the adapter and builds a new one within a second or two,
which is the hardest thing this dataplane does. Four rules keep it survivable,
each of which was a bug first:

- **The rollback is never abandoned.** `winroute` runs its undo pass on its own
  context with a two-minute budget, ignoring the caller's. Teardown is routinely
  reached with a context that is already cancelled, and honouring it aborted
  every remaining `netsh` call instantly - leaving capture routes behind and the
  next connect unable to come up at all.
- **Adapter creation retries.** `WintunCloseAdapter` returns before Windows has
  finished removing the device node, so a fast reconnect meets its own leftover
  adapter. `tun.Open` retries for a couple of seconds before giving up.
- **A stale physical route is refused, not used.** If the interface the routing
  table calls "the way to the internet" no longer exists, or is the adapter just
  created, the dataplane refuses to start rather than pinning every direct flow
  to a dead interface. Being unable to *check* is not the same as failing the
  check, and only the second refuses.
- **Falling back is loud and not permanent.** A failed start is retried once,
  and the diagnostic says what it costs: the tunnel keeps working for domain and
  IP rules, so nothing looks wrong until someone notices that process rules
  stopped reaching the applications that ignore the Windows proxy setting.

The same shape applies one level up: `NativeProcessAttribution` pauses for
twenty seconds after repeated helper failures instead of disabling itself for
the life of the application, which used to mean process rules stayed dead until
the app was quit entirely.

## What has been executed, and where

The pure logic - policy order, DNS parsing, the routing plan and its journal, the SOCKS5 wire
format, owner attribution - is covered by `go test ./...`.

The Windows binary itself has been run under Wine, which implements enough of `iphlpapi` and
the token APIs to exercise the parts that used to be guesses. Confirmed working there:

- start-up with no panic, `--print-capabilities`, and the full `--stdio` handshake;
- `GetExtendedTcpTable` **and** `GetExtendedUdpTable`, including the `MIB_UDPROW_OWNER_PID`
  layout and the network-order port field - a UDP socket opened by the test process came back
  with the right address, port, PID and image name;
- `GetBestRoute` and its `MIB_IPFORWARDROW` layout, through `winnet.LookupEgress`;
- the token elevation check, and the ordered bring-up in `StartWindows` down to the point
  where it asks for `wintun.dll` and reports its absence cleanly;
- IPv6 capture disabling itself, with the intended diagnostic, when no IPv6 route exists.

To repeat it: `wine64 native/windows/x64/shadow-ssh-service.exe --print-capabilities`.

## What still needs a real Windows machine

Wine has no WinTun driver and no useful `netsh`, so everything past adapter creation is still
unobserved. Each of the following is a considered guess rather than a fact:

- **`netsh` argument forms.** Whether `name=<index>` and `interface=<index>` are accepted in
  every position used, and whether `delete route` without `nexthop=` removes what was added.
- **On-link capture routes.** The `/1` routes are added with no next hop. If Windows refuses
  them on a WinTun interface they need `nexthop=` pointing at the adapter's own address.
- **`GetBestRoute` next hop.** The struct and byte order are confirmed; the on-link case
  (`ForwardNextHop == 0`) on a real LAN is not.
- **`IP_UNICAST_IF` byte order.** IPv4 wants network order, IPv6 host order; getting it wrong
  does not fail loudly, it just uses the wrong interface. Symptom: direct flows hang.
- **Adapter shutdown latency.** `ReceivePacket` holds the adapter's shared lock across a
  250 ms bounded wait, so `Close` blocks for up to that long. That is deliberate - it is what
  makes it impossible for the driver to free the ring underneath a call already inside it -
  but it means teardown is not instant.
- **MTU.** 1420 is a guess that leaves room for the transport's framing; if large transfers
  stall, this is the first thing to change. Note the adapter is never told this value - only
  the userspace stack is - so a mismatch shows up as stalls rather than as an error.
- **IPv6.** Capture is disabled automatically when the transport's server is reachable only
  over IPv6, or when no IPv6 route exists to pin direct traffic to. Both cases are logged. On a
  dual-stack network with capture off, a selected application's IPv6 traffic is not captured.

A first run should be checked in this order: the adapter appears in network settings, `route
print` shows the two `/1` routes and the transport's host route, a selected application's TCP
reaches the internet, an unselected one still does, and `route print` is clean again after
disconnect.
