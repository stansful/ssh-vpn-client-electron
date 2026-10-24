import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { access, readdir, rm } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { parseEndpoint } from "../core/network/socks5-check.js";
import { passedTunnelCheck, probeTunnelEndpoint } from "../core/network/tunnel-probe.js";
import { RoutingMatcher, type RoutingMatcherSummary } from "../core/routing/routing-matcher.js";
import { listWindowsProcessConnections, type WindowsProcessConnection } from "../core/network/windows-process-connections.js";
import { listWindowsDnsCacheEntries, type WindowsDnsCacheEntry } from "../core/network/windows-dns-cache.js";
import { WindowsSystemProxyManager, type SystemProxyApplyResult } from "../core/network/windows-system-proxy.js";
import { Socks5Proxy } from "../core/network/socks5-proxy.js";
import { ProxyActivityHeartbeat, PROXY_HEARTBEAT_INTERVAL_MS } from "../core/network/proxy-activity-heartbeat.js";
import { openSocks5UpstreamChannel } from "../core/network/socks5-upstream.js";
import { LocalRoutingEnforcer, RoutingDecisionLog, type LocalRoutingContext } from "./local-routing-enforcement.js";
import { NativeDataplaneController, type DataplaneController } from "./native-dataplane.js";
import { buildSelectedRulesWithProcessIps, ProcessRouteLearner, supportsDynamicProcessRouting } from "./process-route-learning.js";
import {
  errorText,
  MAXIMUM_TUN_UNEXPECTED_STOPS,
  resolveProtectedAddresses,
  startDataplaneWithRetry,
  TUN_ADAPTER_NAME,
  TUN_ROUTING_JOURNAL_FILE,
  TUN_UNEXPECTED_STOP_WINDOW_MS
} from "./tun-routing.js";
import { NativeProcessAttribution, type ProcessAttribution } from "./process-attribution.js";
import { buildXrayConfig, xrayLocalRuleOverrides, type XrayLocalRuleOverrides } from "../core/proxy/xray-config.js";
import { parseHysteria2Link } from "../core/proxy/hysteria2-link.js";
import type { ServiceEvent } from "../shared/ipc.js";
import { proxyProtocolLabel } from "../shared/proxy-protocols.js";
import type {
  DiagnosticsEntry,
  ProxyConnectRequest,
  ProxyProfile,
  RoutingRule,
  RoutingUpdateRequest,
  RuntimeStatus,
  TunnelCheckResult
} from "../shared/types.js";
import { formatServiceTarget, sameLocalProxy } from "./live-ssh-service.js";
import {
  detectXrayVersion,
  reserveDistinctLocalTcpPorts,
  terminateProcess,
  waitForProcessStartup,
  type XrayProcess
} from "./xray/process-utils.js";
import {
  forgetXrayInboundPorts,
  preferredLocalProxyPort,
  preferredXrayInboundPorts,
  rememberLocalProxyPort,
  rememberXrayInboundPorts
} from "./local-proxy-port.js";

export interface XrayServiceBridgeOptions {
  pacDirectory?: string;
  /**
   * Where earlier versions wrote Xray's config, swept of what they left
   * behind - the config itself now goes to Xray on stdin - and the last
   * fallback for the TUN routing journal's folder.
   */
  runtimeDirectory: string;
  executablePath?: string;
  systemProxy?: WindowsSystemProxyManager;
  processRoutingRefreshIntervalMs?: () => number;
  processConnectionsProvider?: (processNames: Iterable<string>) => Promise<WindowsProcessConnection[]>;
  processDnsEntriesProvider?: (addresses: Iterable<string>) => Promise<WindowsDnsCacheEntry[]>;
  /** Path to the native helper used for per-connection process attribution. */
  nativeServiceExecutablePath?: string;
  /**
   * The application's data folder. It is where the TUN routing journal lives,
   * and one of the places the helper is told to look for `wintun.dll` - a
   * portable build's own resources folder is recreated in `%TEMP%` at every
   * launch, so nothing a user puts there survives.
   */
  userDataDirectory?: string;
  /** Injection seam for tests; defaults to the native helper when a path is set. */
  processAttribution?: ProcessAttribution;
  /** Injection seam for tests; defaults to the native helper when a path is set. */
  dataplane?: DataplaneController;
  /** Injection seam for tests; defaults to a DNS lookup of the profile host. */
  protectedAddressResolver?: (host: string) => Promise<string[]>;
  /**
   * Injection seam for tests; defaults to asking the binary (`xray version`),
   * once per binary. The answer picks the config shape where Xray releases
   * differ.
   */
  xrayVersionProvider?: (executablePath: string) => Promise<string | undefined>;
  /**
   * Injection seam for tests; defaults to binding the ports on loopback. Keeps
   * a stopped Xray's inbound ports while routing still points at them (see
   * {@link XrayServiceBridge.occupyHeldPorts}).
   */
  holdInboundPorts?: (endpoints: ReadonlyArray<{ host: string; port: number }>) => Promise<HeldInboundPorts>;
}

/** Ports kept bound while nothing else may have them. */
export interface HeldInboundPorts {
  release(): Promise<void>;
}

/**
 * A restart that waiting cannot fix: the runtime is gone - quarantined by an
 * antivirus, deleted, moved with the app - or the profile no longer makes a
 * config Xray accepts. Retrying it every few minutes forever only hides why.
 */
class XrayRestartBlockedError extends Error {}

const MAX_LOCAL_PROXY_DIAGNOSTICS = 80;
/**
 * Xray writes one `[Info] ... accepted ...` line per connection, and a client
 * like Telegram opens hundreds in a minute. A single shared budget therefore
 * spent itself on chatter within seconds and then detached the stream
 * altogether, so the `[Warning]` explaining why the outbound was failing never
 * reached the log - the one line anyone actually needed.
 *
 * Warnings and errors get their own budget that the chatter cannot touch.
 */
const MAX_XRAY_IMPORTANT_LOG_LINES = 200;
const MAX_XRAY_ROUTINE_LOG_LINES = 40;
const MAX_XRAY_PROCESS_LOG_CHUNK_CHARACTERS = 64 * 1024;
const MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS = 4096;
/**
 * Xray's whole explanation for a config it cannot load is one unmarked stdout
 * line, printed just before it exits with code 23 - and that exit can be seen
 * before the line has been read. A failed startup waits this long for it.
 */
const XRAY_STARTUP_OUTPUT_DRAIN_MS = 1_000;
const MAX_XRAY_STARTUP_REASON_CHARACTERS = 400;
const XRAY_STARTUP_FAILURE_PREFIX = /^Failed to start:\s*/u;
/**
 * Xray reads its whole config from stdin and then never touches stdin again,
 * so the credentials in it - UUID, password, Hysteria 2 auth, REALITY keys -
 * never reach the disk. They used to sit in `<userData>/xray/xray-config.json`
 * for the whole session, and past it after a crash or a logoff.
 */
const XRAY_CONFIG_FROM_STDIN = "stdin:";
/** The file earlier versions wrote the config to; swept at startup. */
const LEGACY_RUNTIME_CONFIG_FILE = "xray-config.json";
/**
 * How long routing stays pointed at Xray after it stopped unexpectedly, the
 * same hold the SSH transport keeps while it reconnects: traffic meant for
 * the tunnel fails instead of leaking out directly, and a restart within the
 * hold - on the same ports, see {@link preferredXrayInboundPorts} - takes over
 * without the system proxy or the adapter ever being taken down.
 */
const ROUTING_HOLD_TIMEOUT_MS = 30_000;
const HYSTERIA2_INSECURE_WARNING =
  "This link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so the server’s certificate is checked as usual. If the server uses a self-signed certificate, add its pinSHA256 to the link.";
/**
 * Hysteria 2 is QUIC, so it is UDP end to end. Xray's local listeners come up
 * whether or not a single datagram reaches the server, which makes a failed
 * check the first sign of a network that drops UDP. The hint has to name the
 * other suspects itself: Xray logs a Hysteria 2 dial failure (auth refused,
 * certificate mismatch, timeout) at [Info], below the "warning" level the
 * runtime runs at, so its reason never reaches the Activity log.
 */
const HYSTERIA2_TUNNEL_CHECK_HINT =
  "Hysteria 2 runs over UDP (QUIC): the network may block UDP to the server or its ports, or the link’s password (auth), certificate pin (pinSHA256) or obfs password may be wrong.";
/** Clears what describes a session, for a status that no longer has one. */
const CLEARED_SESSION_STATUS = {
  activeConfigId: undefined,
  activeConfigName: undefined,
  activeTarget: undefined,
  connectedAt: undefined,
  reconnectAttempt: 0,
  realTunnelAvailable: false
} as const satisfies Partial<RuntimeStatus>;

export class XrayServiceBridge {
  private readonly events = new EventEmitter();
  private readonly systemProxy: WindowsSystemProxyManager;
  private readonly executablePath: string | undefined;
  private readonly xrayVersionProvider: (executablePath: string) => Promise<string | undefined>;
  private status: RuntimeStatus;
  private process: XrayProcess | undefined;
  /** The process whose listeners are being awaited; its exit is reported by the startup path. */
  private startingProcess: XrayProcess | undefined;
  private socksEndpoint: { host: string; port: number } | undefined;
  private httpEndpoint: { host: string; port: number } | undefined;
  /**
   * The user's rules for the local network that the running process's config
   * carries (see xrayLocalRuleOverrides), as a signature: Xray reads them only
   * at start, so a change to them needs a restart.
   */
  private runningLocalRuleOverrides: string | undefined;
  /** Lets a disconnect stop waiting for a TUN start in flight; see abandonTunStart. */
  private tunStartAbort: AbortController | undefined;
  private lastRequest: ProxyConnectRequest | undefined;
  private disconnectRequested = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  /**
   * Routing is still pointed at an Xray that stopped unexpectedly, waiting
   * for a restart to take it over. True from the failure until a restart
   * succeeds or the routing is torn down - including the moment between the
   * hold running out and its teardown getting its turn in the queue.
   */
  private routingHeld = false;
  private routingHoldTimer: NodeJS.Timeout | undefined;
  private routingHoldGeneration = 0;
  /** The inbounds held routing points at: those of the Xray that stopped. */
  private heldRoutingEndpoints: Array<{ host: string; port: number }> = [];
  /** Those inbounds' ports, bound here while no Xray has them. */
  private heldInboundPorts: HeldInboundPorts | undefined;
  private readonly holdInboundPorts: (endpoints: ReadonlyArray<{ host: string; port: number }>) => Promise<HeldInboundPorts>;
  private startupAbortController: AbortController | undefined;
  private routingRules: RoutingRule[] = [];
  private processRoutingMonitor: NodeJS.Timeout | undefined;
  private processRoutingGeneration = 0;
  private readonly processRoutes: ProcessRouteLearner;
  private readonly processAttribution: ProcessAttribution | undefined;
  private readonly dataplane: DataplaneController | undefined;
  private readonly dataplaneJournalPath: string;
  private readonly protectedAddressResolver: (host: string) => Promise<string[]>;
  private tunRoutingActive = false;
  /**
   * A dataplane start was sent and no stop has followed. A start that failed
   * here may still have succeeded in the helper, so a stop is owed for it.
   */
  private tunStartAttempted = false;
  /**
   * The server addresses the running adapter keeps off itself, and the host
   * they were resolved for. A re-apply whose lookup fails for a moment - right
   * after a resume, a flaky resolver - keeps them rather than taking down an
   * adapter that was routing fine.
   */
  private tunProtectedAddresses: { host: string; addresses: string[] } | undefined;
  /** When the adapter stopped on its own during this session, for {@link MAXIMUM_TUN_UNEXPECTED_STOPS}. */
  private tunUnexpectedStops: number[] = [];
  /** Set once the adapter kept stopping; the session then stays on the proxy path. */
  private tunSuspendedReason: string | undefined;
  private readonly localRoutingEnforcer: LocalRoutingEnforcer;
  private localRoutingContext: LocalRoutingContext | undefined;
  /** Xray's SOCKS inbound, where the local routing listener forwards selected traffic. */
  private localRoutingUpstream: { host: string; port: number } | undefined;
  private localProxy: Socks5Proxy | undefined;
  private localProxyEndpoint: { host: string; port: number } | undefined;
  private localProxyHeartbeat: NodeJS.Timeout | undefined;
  private proxyDiagnostics = 0;
  /**
   * Both directions of every routing decision, so the log can tell "no rule
   * matched" apart from "the rules matched and the tunnel behind them is
   * dead". See {@link RoutingDecisionLog}.
   */
  private readonly routingDecisions = new RoutingDecisionLog((message) => this.appendDiagnostic("info", message));
  private importantProcessLogLines = 0;
  private routineProcessLogLines = 0;
  private readonly processLogDrainers = new WeakMap<XrayProcess, () => void>();
  /** The last "Failed to start" reason each process printed, redacted and bounded. */
  private readonly processStartupFailures = new WeakMap<XrayProcess, string>();
  private mutationTail: Promise<void> = Promise.resolve();
  private lifecycleGeneration = 0;
  private routingGeneration = 0;
  private disposed = false;

  constructor(initialStatus: RuntimeStatus, options: XrayServiceBridgeOptions) {
    this.systemProxy = options.systemProxy ?? new WindowsSystemProxyManager({ pacDirectory: options.pacDirectory });
    this.processRoutes = new ProcessRouteLearner({
      connectionsProvider: options.processConnectionsProvider ?? listWindowsProcessConnections,
      dnsEntriesProvider: options.processDnsEntriesProvider ??
        (options.processConnectionsProvider ? async () => [] : listWindowsDnsCacheEntries),
      refreshIntervalMs: options.processRoutingRefreshIntervalMs,
      onWarning: (message) => this.appendDiagnostic("warning", message),
      transportLabel: " for Xray transport"
    });
    this.processAttribution = options.processAttribution ?? (options.nativeServiceExecutablePath
      ? new NativeProcessAttribution({
          executablePath: options.nativeServiceExecutablePath,
          onDiagnostic: (level, message) => this.appendDiagnostic(level, message)
        })
      : undefined);
    this.dataplane = options.dataplane ?? (options.nativeServiceExecutablePath
      ? new NativeDataplaneController({
          executablePath: options.nativeServiceExecutablePath,
          // The PAC directory lives inside the application's data folder, which
          // is a place the user can actually put wintun.dll - unlike the
          // packaged resources of a portable build.
          userDataDirectory: options.userDataDirectory,
          onDiagnostic: (level, message) => this.appendDiagnostic(level === "error" ? "error" : level, message),
          onActiveChange: () => this.syncDerivedStatus()
        })
      : undefined);
    this.dataplane?.onUnexpectedStop?.((reason) => this.handleDataplaneUnexpectedStop(reason));
    this.dataplaneJournalPath = path.join(options.userDataDirectory ?? options.pacDirectory ?? options.runtimeDirectory, TUN_ROUTING_JOURNAL_FILE);
    this.protectedAddressResolver = options.protectedAddressResolver ?? resolveProtectedAddresses;
    this.localRoutingEnforcer = new LocalRoutingEnforcer(this.processAttribution);
    // The config no longer touches the disk, but one an earlier version left
    // behind - after a crash, or a logoff mid-session - still holds a profile's
    // credentials in plaintext.
    void sweepLegacyRuntimeConfigs(options.runtimeDirectory);
    this.executablePath = options.executablePath;
    this.xrayVersionProvider = options.xrayVersionProvider ?? detectXrayVersion;
    this.holdInboundPorts = options.holdInboundPorts ?? bindRefusingLoopbackPorts;
    this.status = {
      ...initialStatus,
      state: "Disconnected",
      transport: "xray",
      realTunnelAvailable: false,
      message: "Xray transport is ready.",
      ...this.derivedStatus()
    };
  }

  onEvent(listener: (event: ServiceEvent) => void): () => void {
    this.events.on("event", listener);
    return () => this.events.off("event", listener);
  }

  getStatus(): RuntimeStatus {
    return structuredClone(this.status);
  }

  updateRoutingRules(rules: RoutingRule[]): Promise<void> {
    if (this.disposed) {
      return Promise.resolve();
    }
    this.routingRules = rules;
    if (this.lastRequest) {
      this.lastRequest = { ...this.lastRequest, routingRules: rules };
    }
    const routingGeneration = ++this.routingGeneration;
    const lifecycleGeneration = this.lifecycleGeneration;
    return this.enqueueMutation(async () => {
      if (!this.isCurrentMutation(lifecycleGeneration, routingGeneration)) {
        return;
      }
      const summary = new RoutingMatcher("selected-rules", rules).summary();
      const request = this.lastRequest;
      const socksEndpoint = this.socksEndpoint;
      if (this.status.state === "Connected" && request && socksEndpoint) {
        this.appendDiagnostic(
          "info",
          `Routing rules changed while Xray transport is connected: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing.`
        );
        if (this.restartForLocalRuleChange(request)) {
          return;
        }
        await this.applySystemRouting(request, socksEndpoint);
        // The apply may have left the adapter or the routing listener for the
        // path that does use Xray's own HTTP inbound.
        this.restartForLocalRuleChange(request);
        return;
      }
      this.appendDiagnostic(
        "info",
        `Routing rules prepared for Xray transport: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
      );
    });
  }

  updateRouting(update: RoutingUpdateRequest): Promise<void> {
    if (this.disposed) {
      return Promise.resolve();
    }
    this.routingRules = update.routingRules;
    if (this.lastRequest) {
      this.lastRequest = {
        ...this.lastRequest,
        routingMode: update.routingMode,
        routingRules: update.routingRules,
        routingProxyDomains: update.routingProxyDomains,
        routingDirectDomains: update.routingDirectDomains,
        checkEndpoint: update.checkEndpoint
      };
    }
    const routingGeneration = ++this.routingGeneration;
    const lifecycleGeneration = this.lifecycleGeneration;
    return this.enqueueMutation(async () => {
      if (!this.isCurrentMutation(lifecycleGeneration, routingGeneration)) {
        return;
      }
      const summary = new RoutingMatcher(update.routingMode, update.routingRules).summary();
      const request = this.lastRequest;
      const socksEndpoint = this.socksEndpoint;
      if (this.status.state === "Connected" && request && socksEndpoint) {
        if (this.restartForLocalRuleChange(request)) {
          return;
        }
        this.appendDiagnostic(
          "info",
          `Routing mode changed while Xray transport is connected: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Re-applying routing without Xray restart.`
        );
        await this.applySystemRouting(request, socksEndpoint);
        // The apply may have left the adapter or the routing listener for the
        // path that does use Xray's own HTTP inbound.
        this.restartForLocalRuleChange(request);
        return;
      }
      this.appendDiagnostic(
        "info",
        `Routing prepared for Xray transport: mode=${update.routingMode}, enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}.`
      );
    });
  }

  /**
   * A profile was renamed. The session it runs takes the new name at once -
   * the name is only a label, so Xray keeps running - and so does a restart.
   */
  renameActiveProfile(profileId: string, name: string): void {
    if (this.disposed) {
      return;
    }
    if (this.lastRequest?.profile.id === profileId) {
      this.lastRequest = { ...this.lastRequest, profile: { ...this.lastRequest.profile, name } };
    }
    if (this.status.activeConfigId === profileId && this.status.activeConfigName !== name) {
      this.setStatus({ activeConfigName: name });
    }
  }

  connect(request: ProxyConnectRequest): Promise<void> {
    if (this.disposed) {
      return Promise.reject(new Error("Xray service has been disposed."));
    }
    // A new session: the adapter gets another chance.
    this.tunUnexpectedStops = [];
    this.tunSuspendedReason = undefined;
    return this.startConnect(request, false);
  }

  /**
   * A connect the user asked for, or - with `restart` - one attempt of the
   * automatic restart after Xray stopped unexpectedly. A failed restart is
   * rescheduled with the backoff instead of ending in Error, and keeps the
   * routing hold rather than tearing routing down first - unless no attempt
   * could work (isBlockedRestart: the runtime is gone, or the config is
   * refused), which gives the routing back and ends in Error.
   */
  private startConnect(request: ProxyConnectRequest, restart: boolean): Promise<void> {
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    this.lastRequest = request;
    this.routingRules = request.routingRules;
    this.routingGeneration += 1;
    this.disconnectRequested = false;
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Connecting",
      activeConfigId: request.profile.id,
      activeConfigName: request.profile.name,
      activeTarget: formatServiceTarget(request.profile.host, request.profile.port),
      connectedAt: undefined,
      // A restart keeps counting, so a failed one backs off further.
      ...(restart ? {} : { reconnectAttempt: 0 }),
      realTunnelAvailable: false,
      message: `Starting ${proxyProtocolLabel(request.profile.protocol)} profile ${request.profile.name}.`
    });
    return this.enqueueMutation(() => this.connectInternal(request, generation, restart));
  }

  private async connectInternal(request: ProxyConnectRequest, generation: number, restart: boolean): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.importantProcessLogLines = 0;
    this.routineProcessLogLines = 0;
    // Both budgets are per connection attempt. Left unreset, a long-lived
    // process went permanently silent after its first busy session.
    this.proxyDiagnostics = 0;
    this.routingDecisions.reset();
    if (!(restart && this.routingHeld)) {
      // A restart that takes held routing over keeps what process discovery
      // learned: the held PAC still lists it, and a destination that went
      // through the proxy is never seen connecting directly again, so it
      // would go out directly until discovery happened to learn it anew.
      this.processRoutes.clear();
    }
    this.processRoutes.warningEmitted = false;
    // Held routing is what a restart takes over: applying it again below
    // swaps the rules and Xray's ports in place, where tearing it down first
    // would let traffic out directly for the length of the startup.
    if (!(restart && this.routingHeld)) {
      await this.stopRouting();
    }
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    await this.stopXrayProcess(this.process);
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    if (restart && this.routingHeld) {
      // A restart the service chose (see restartForLocalRuleChange) stops a
      // process that was still running: its ports are held from here, as an
      // unexpected stop holds them, until the new process binds them.
      await this.occupyHeldPorts();
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
    }
    this.appendDiagnostic(
      "info",
      `Xray connect requested for ${describeProfileEndpoint(request.profile)}, transport=${request.profile.transport}, security=${request.profile.security}, routing=${request.routingMode}.`
    );
    if (hasUnpinnedInsecureFlag(request)) {
      this.appendDiagnostic("warning", HYSTERIA2_INSECURE_WARNING);
    }

    let acquiredProcess: XrayProcess | undefined;
    try {
      const executablePath = await this.requireExecutablePath();
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      // Unknown is fine: the config then takes the bundled release's shape.
      const xrayVersion = await Promise.resolve()
        .then(() => this.xrayVersionProvider(executablePath))
        .catch(() => undefined);
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      // The held ports go back just before Xray binds them; nobody else had
      // them while it was down.
      await this.releaseHeldPorts();
      // The same ports as last time where they are still free: they are what
      // the app advertises as the local proxy, and what a held adapter or
      // system proxy is still pointed at. The routing listener's port is never
      // one of them, or the two would race for it.
      const preferredPorts = preferredXrayInboundPorts();
      const [socksEndpoint, httpEndpoint] = await reserveDistinctLocalTcpPorts(2, undefined, {
        preferredPorts: [preferredPorts?.socksPort, preferredPorts?.httpPort],
        avoidPorts: [preferredLocalProxyPort(), this.localProxyEndpoint?.port]
      });
      if (!socksEndpoint || !httpEndpoint) {
        throw new Error("Unable to reserve distinct Xray listener ports.");
      }
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      let config: string;
      // The rules as they are now: a routing update may have landed since
      // this attempt began.
      const localRuleOverrides = localRuleOverridesFor((this.lastRequest ?? request).routingRules);
      try {
        config = buildXrayConfig({
          rawUri: request.secrets.rawUri,
          socksHost: socksEndpoint.host,
          socksPort: socksEndpoint.port,
          httpHost: httpEndpoint.host,
          httpPort: httpEndpoint.port,
          xrayVersion,
          localNetworkDirect: localRuleOverrides !== undefined,
          localRuleOverrides
        });
      } catch (error) {
        throw new XrayRestartBlockedError(error instanceof Error ? error.message : String(error));
      }
      const processHandle = spawn(executablePath, ["run", "-config", XRAY_CONFIG_FROM_STDIN], {
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true
      });
      acquiredProcess = processHandle;
      this.process = processHandle;
      this.runningLocalRuleOverrides = JSON.stringify(localRuleOverrides);
      this.attachProcessLogging(processHandle, generation);
      processHandle.on("error", (error) => this.handleXrayFailure(processHandle, generation, error));
      // A process that died before reading its config reports that through
      // its exit; the broken pipe on top of it says nothing more.
      processHandle.stdin.on("error", () => undefined);
      processHandle.stdin.end(config, "utf8");
      const outputClosed = new Promise<void>((resolve) => processHandle.once("close", () => resolve()));
      processHandle.once("close", (code, signal) => {
        this.handleXrayClose(processHandle, generation, code, signal);
      });
      const startupAbortController = new AbortController();
      this.startupAbortController = startupAbortController;
      this.startingProcess = processHandle;
      try {
        await waitForProcessStartup(processHandle, [socksEndpoint, httpEndpoint], {
          signal: startupAbortController.signal
        });
        rememberXrayInboundPorts({ socksPort: socksEndpoint.port, httpPort: httpEndpoint.port });
      } catch (error) {
        // Xray exits when it cannot bind, and a remembered port can be taken
        // between the check above and Xray's own bind: the next attempt then
        // starts from fresh ports instead of failing on the same one again.
        const exited = processHandle.exitCode !== null || processHandle.signalCode !== null;
        if (
          exited &&
          (socksEndpoint.port === preferredPorts?.socksPort || httpEndpoint.port === preferredPorts?.httpPort)
        ) {
          forgetXrayInboundPorts();
        }
        throw new Error(await this.describeStartupFailure(processHandle, error, outputClosed));
      } finally {
        if (this.startupAbortController === startupAbortController) {
          this.startupAbortController = undefined;
        }
        if (this.startingProcess === processHandle) {
          this.startingProcess = undefined;
        }
      }
      if (!this.isCurrentLifecycle(generation) || this.process !== processHandle) {
        await this.cleanupProcessResources(processHandle);
        return;
      }
      this.socksEndpoint = socksEndpoint;
      this.httpEndpoint = httpEndpoint;
      const effectiveRequest = this.lastRequest ?? request;
      await this.applySystemRouting(effectiveRequest, socksEndpoint);
      if (!this.isCurrentLifecycle(generation) || this.process !== processHandle) {
        await this.cleanupProcessResources(processHandle);
        return;
      }
      // Routing now points at this process: whatever was held is taken over.
      this.clearRoutingHold();
      this.heldRoutingEndpoints = [];
      this.setStatus({
        state: "Connected",
        activeConfigId: effectiveRequest.profile.id,
        activeConfigName: effectiveRequest.profile.name,
        activeTarget: formatServiceTarget(effectiveRequest.profile.host, effectiveRequest.profile.port),
        connectedAt: new Date().toISOString(),
        reconnectAttempt: 0,
        realTunnelAvailable: true,
        message: `Connected to ${effectiveRequest.profile.name}. Xray HTTP proxy ${httpEndpoint.host}:${httpEndpoint.port} and SOCKS proxy ${socksEndpoint.host}:${socksEndpoint.port} are live.`
      });
      this.appendDiagnostic(
        "info",
        `Xray runtime${xrayVersion ? ` ${xrayVersion}` : ""} started for ${describeProfileEndpoint(effectiveRequest.profile)}.`
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.cleanupProcessResources(acquiredProcess);
      if (!this.isCurrentLifecycle(generation)) {
        return;
      }
      if (restart && !this.disconnectRequested && !isBlockedRestart(error)) {
        // A port race, a slow start or a proxy that failed to apply is no
        // reason to give up a session the user still wants: the next attempt
        // waits out a longer backoff, and wake() can bring it forward.
        this.appendDiagnostic("error", `Xray restart failed: ${message}`);
        if (this.routingHeld) {
          await this.occupyHeldPorts();
        }
        this.scheduleReconnect(message, generation);
        return;
      }
      if (restart && this.routingHeld) {
        // Nothing will take the held routing over: the machine goes back to
        // direct routing now, not when the hold runs out.
        await this.stopRouting();
      }
      this.setStatus({
        state: "Error",
        activeConfigId: request.profile.id,
        realTunnelAvailable: false,
        message
      });
      this.appendDiagnostic("error", message);
    }
  }

  disconnect(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.endSessionNow();
    const generation = this.lifecycleGeneration;
    // Only the tunnel comes down here. The dataplane controller and the
    // attribution helper survive: disposing them is permanent, and doing it on
    // an ordinary disconnect left every later connect reporting "the dataplane
    // controller is disposed" and quietly falling back to the proxy path, where
    // domain rules keep working and process rules do not.
    return this.enqueueMutation(() => this.disconnectInternal(generation));
  }

  /**
   * The part of disconnect() that must not wait its turn: the session is
   * marked as ending, and an Xray start or TUN start in flight stops being
   * waited for. Main calls it before it queues the disconnect behind
   * whatever it is running - a Connect, a routing update - which would
   * otherwise sit out that work's own timeouts first; the queued
   * disconnect() then tears down. Does nothing unless a session is live or
   * on its way.
   */
  beginDisconnect(): void {
    const state = this.status.state;
    if (this.disposed || (state !== "Connecting" && state !== "Reconnecting" && state !== "Connected")) {
      return;
    }
    this.endSessionNow();
  }

  /**
   * Everything a disconnect does before its teardown's turn comes: whatever
   * is in flight belongs to a lifecycle that ends here, and reads as
   * overtaken from now on.
   */
  private endSessionNow(): void {
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    this.abandonTunStart();
    this.lifecycleGeneration += 1;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Disconnecting Xray transport."
    });
  }

  private async disconnectInternal(generation: number): Promise<void> {
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    const processHandle = this.process;
    this.process = undefined;
    await this.stopRouting();
    await this.stopXrayProcess(processHandle);
    if (!this.isCurrentLifecycle(generation)) {
      return;
    }
    this.setStatus({
      state: "Disconnected",
      ...CLEARED_SESSION_STATUS,
      message: "Disconnected."
    });
    this.appendDiagnostic("info", "Xray transport disconnected.");
  }

  /**
   * Dismisses an error the user has read: Error becomes Disconnected and no
   * restart follows. A failed connect releases routing on the way into Error;
   * routing still held for the restart an unexpected stop would have started
   * is released here, since nothing will take it over now.
   */
  clearError(): Promise<void> {
    if (this.disposed || this.status.state !== "Error") {
      return Promise.resolve();
    }
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    this.abandonTunStart();
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnected",
      ...CLEARED_SESSION_STATUS,
      message: "Disconnected."
    });
    if (!this.routingHeld) {
      return Promise.resolve();
    }
    return this.enqueueMutation(async () => {
      if (this.isCurrentLifecycle(generation) && this.routingHeld) {
        await this.stopRouting();
      }
    });
  }

  async checkTunnel(endpoint: string): Promise<TunnelCheckResult> {
    const at = new Date().toISOString();
    if (!this.socksEndpoint || this.status.state !== "Connected") {
      const result = { endpoint, ok: false, at, message: "Xray transport is not connected." };
      this.appendDiagnostic("warning", `Tunnel check skipped for ${endpoint}: Xray transport is not connected.`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }

    // Captured before the probe: the property can be replaced by a concurrent
    // reconnect, and a check must report on the tunnel it started against.
    const socksEndpoint = this.socksEndpoint;
    const protocol = this.lastRequest?.profile.protocol;
    try {
      this.appendDiagnostic("info", `Xray tunnel check requested for ${endpoint}.`);
      const startedAt = Date.now();
      const target = parseEndpoint(endpoint);
      // Not just the SOCKS reply: Xray answers that as soon as it has chosen an
      // outbound, so a dead VMess outbound used to pass this check while every
      // real connection through it hung.
      const probe = await probeTunnelEndpoint(
        (signal) => openSocks5UpstreamChannel(socksEndpoint, target, { signal }),
        target
      );
      const result = passedTunnelCheck(endpoint, at, Date.now() - startedAt, probe);
      this.appendDiagnostic(probe.outcome === "unverified" ? "warning" : "info", result.message);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      const result = {
        endpoint,
        ok: false,
        at,
        message: protocol === "hysteria2"
          ? `${/[.!?]$/u.test(reason) ? reason : `${reason}.`} ${HYSTERIA2_TUNNEL_CHECK_HINT}`
          : reason
      };
      this.appendDiagnostic("warning", `Xray tunnel check failed for ${endpoint}: ${result.message}`);
      this.emit({ type: "tunnel-check-result", result });
      return result;
    }
  }

  async openTerminal(): Promise<void> {
    this.emitError("SSH terminal is available only for SSH transport.");
  }

  async closeTerminal(): Promise<void> {
    return Promise.resolve();
  }

  async terminalInput(input: string): Promise<void> {
    void input;
    this.emitError("SSH terminal is available only for SSH transport.");
  }

  dispose(): Promise<void> {
    if (this.disposed) {
      return this.mutationTail;
    }
    this.disposed = true;
    this.disconnectRequested = true;
    this.clearReconnectTimer();
    this.cancelProcessStartup();
    this.abandonTunStart();
    const generation = ++this.lifecycleGeneration;
    this.setStatus({
      state: "Disconnecting",
      realTunnelAvailable: false,
      message: "Stopping Xray service."
    });
    return this.enqueueMutation(async () => {
      await this.disconnectInternal(generation);
      // An adapter left up on quit would keep capture routes pointing at a
      // process that no longer exists.
      await this.dataplane?.dispose().catch(() => undefined);
      await this.processAttribution?.dispose().catch(() => undefined);
    });
  }

  private async requireExecutablePath(): Promise<string> {
    const executablePath = this.executablePath;
    if (!executablePath) {
      throw new XrayRestartBlockedError("Xray runtime is not configured. Set SHADOW_SSH_XRAY_PATH or bundle resources/xray/<platform>/<arch>/xray.");
    }
    try {
      await access(executablePath);
      return executablePath;
    } catch {
      throw new XrayRestartBlockedError(`Xray runtime was not found at ${executablePath}.`);
    }
  }

  private handleXrayClose(
    processHandle: XrayProcess,
    generation: number,
    code: number | null,
    signal: NodeJS.Signals | null
  ): void {
    // An exit during startup is the startup path's to report, together with
    // the reason Xray printed for it.
    if (this.process !== processHandle || !this.isCurrentLifecycle(generation) || this.startingProcess === processHandle) {
      return;
    }
    const reason = `Xray runtime exited${code === null ? "" : ` with code ${code}`}${signal ? ` signal ${signal}` : ""}.`;
    this.handleXrayFailure(processHandle, generation, new Error(reason));
  }

  private handleXrayFailure(processHandle: XrayProcess, generation: number, error: Error): void {
    if (this.process !== processHandle || !this.isCurrentLifecycle(generation)) {
      return;
    }
    const failureGeneration = ++this.lifecycleGeneration;
    const inbounds = [this.socksEndpoint, this.httpEndpoint].filter(
      (endpoint): endpoint is { host: string; port: number } => endpoint !== undefined
    );
    this.process = undefined;
    this.socksEndpoint = undefined;
    this.httpEndpoint = undefined;
    this.clearReconnectTimer();
    if (!this.routingHeld) {
      this.heldRoutingEndpoints = inbounds;
    }
    this.holdRouting();
    this.setStatus({
      state: "Error",
      realTunnelAvailable: false,
      message: error.message
    });
    this.appendDiagnostic("error", error.message);
    void this.enqueueMutation(async () => {
      // Routing stays pointed at Xray's ports for the restart to take over;
      // the hold's own deadline returns the machine to direct routing.
      if (!this.routingHeld) {
        await this.stopRouting();
      }
      await this.stopXrayProcess(processHandle);
      if (this.routingHeld && !this.disposed) {
        await this.occupyHeldPorts();
      }
      if (!this.isCurrentLifecycle(failureGeneration) || this.disconnectRequested) {
        return;
      }
      this.scheduleReconnect(error.message, failureGeneration);
    });
  }

  /**
   * Held routing - the system proxy or PAC, the routing listener's upstream,
   * the adapter - still points at the stopped Xray's inbound ports, and those
   * are free once it has exited. Whatever binds one first would receive every
   * captured flow: on a shared machine, another user's process. So they are
   * bound here, refusing every connection, until a restart takes them back. A
   * port that cannot be bound is already someone else's, and the hold is
   * given up at once rather than left pointing at it.
   */
  private async occupyHeldPorts(): Promise<void> {
    if (this.heldInboundPorts || this.heldRoutingEndpoints.length === 0) {
      return;
    }
    try {
      this.heldInboundPorts = await this.holdInboundPorts(this.heldRoutingEndpoints);
    } catch (error) {
      this.appendDiagnostic(
        "warning",
        `Another program took Xray's local port while Xray was down (${error instanceof Error ? error.message : String(error)}); returning the machine to direct routing until Xray is back.`
      );
      await this.stopRouting();
    }
  }

  private async releaseHeldPorts(): Promise<void> {
    const held = this.heldInboundPorts;
    this.heldInboundPorts = undefined;
    await held?.release().catch(() => undefined);
  }

  /**
   * The last thing a quit that ran out of time does: whatever is still
   * queued, the Xray process is not left running once the app is gone.
   */
  killProcessForExit(): void {
    for (const handle of [this.process, this.startingProcess]) {
      if (handle && handle.exitCode === null && handle.signalCode === null) {
        try {
          handle.kill();
        } catch {
          // Already gone.
        }
      }
    }
  }

  /**
   * Xray reads its routing only at start, and the user's rules for the local
   * network are part of it (see xrayLocalRuleOverrides): without them Xray
   * would send a destination such a rule tunnels upstream straight out
   * through its direct outbound. So when an update changes that set, Xray is
   * restarted the way an unexpected stop restarts it - routing stays pointed
   * at its ports, which refuse connections instead of letting them out
   * directly, until the new process takes it over on the same ports, or the
   * hold runs out. Every other routing change is applied in place. Returns
   * whether a restart was started; it runs after the current mutation.
   *
   * Only the HTTP inbound carries those rules, and only the Windows proxy
   * path (PAC or static) sends the machine's traffic there. Under the TUN
   * adapter or the routing listener everything enters through the SOCKS
   * inbound, so a restart would only reset every tunnelled flow for nothing:
   * the change waits, and is caught up with by the next Xray start, or by the
   * first routing apply that ends on the proxy path (its callers ask again).
   */
  private restartForLocalRuleChange(request: ProxyConnectRequest): boolean {
    if (
      !this.process ||
      this.status.state !== "Connected" ||
      !this.systemTrafficEntersHttpInbound() ||
      JSON.stringify(localRuleOverridesFor(request.routingRules)) === this.runningLocalRuleOverrides
    ) {
      return false;
    }
    this.appendDiagnostic(
      "info",
      "Routing rules for the local network changed, which Xray reads only at start: restarting Xray, with routing held until it is back."
    );
    if (!this.routingHeld) {
      this.heldRoutingEndpoints = [this.socksEndpoint, this.httpEndpoint].filter(
        (endpoint): endpoint is { host: string; port: number } => endpoint !== undefined
      );
    }
    this.holdRouting();
    this.restart();
    return true;
  }

  /**
   * Whether the Windows proxy points the machine's traffic at Xray's own HTTP
   * inbound: neither the TUN adapter nor the routing listener is in front of
   * it, both of which hand Xray their flows through its SOCKS inbound.
   */
  private systemTrafficEntersHttpInbound(): boolean {
    return !this.tunRoutingActive && this.localRoutingContext === undefined;
  }

  /**
   * Xray is gone but the session is wanted: keep the adapter, the routing
   * listener and the system proxy pointed at it for now, and start the clock
   * after which the machine is returned to direct routing if no restart has
   * taken them over. Mirrors the SSH transport's hold while it reconnects.
   */
  private holdRouting(): void {
    // Process discovery has nothing to learn while Xray is down; a restart
    // starts it again with routing.
    this.stopProcessRoutingMonitor();
    if (this.routingHeld) {
      return;
    }
    this.routingHeld = true;
    const holdGeneration = ++this.routingHoldGeneration;
    this.routingHoldTimer = setTimeout(() => {
      this.routingHoldTimer = undefined;
      if (holdGeneration !== this.routingHoldGeneration || this.disposed) {
        return;
      }
      // The SSH transport's wording, which the attention store and the
      // routing filter of the diagnostics history both read.
      this.appendDiagnostic(
        "warning",
        `The tunnel has been down for ${Math.round(ROUTING_HOLD_TIMEOUT_MS / 1000)} s; returning the machine to direct routing until the session is back.`
      );
      void this.enqueueMutation(async () => {
        // A restart may have taken the routing over while this waited its
        // turn, and a later outage has a hold of its own.
        if (holdGeneration !== this.routingHoldGeneration || this.disposed || !this.routingHeld) {
          return;
        }
        await this.stopRouting();
      }).catch(() => undefined);
    }, ROUTING_HOLD_TIMEOUT_MS);
    this.routingHoldTimer.unref();
  }

  private clearRoutingHold(): void {
    this.routingHoldGeneration += 1;
    this.routingHeld = false;
    if (this.routingHoldTimer) {
      clearTimeout(this.routingHoldTimer);
      this.routingHoldTimer = undefined;
    }
  }

  private scheduleReconnect(reason: string, generation: number): void {
    if (this.disposed || !this.isCurrentLifecycle(generation) || this.disconnectRequested || !this.lastRequest || this.reconnectTimer) {
      return;
    }
    const attempt = this.status.reconnectAttempt + 1;
    // 1 s doubling to 256 s, plus up to 5 s of jitter: never past 5 minutes.
    const baseDelayMs = Math.min(5 * 60 * 1000, 1000 * 2 ** Math.min(attempt - 1, 8));
    const jitterMs = Math.floor(Math.random() * Math.min(5000, baseDelayMs * 0.2));
    const delayMs = baseDelayMs + jitterMs;
    this.setStatus({
      state: "Reconnecting",
      reconnectAttempt: attempt,
      realTunnelAvailable: false,
      message: `Restarting Xray transport after failure: ${reason}`
    });
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      if (this.isCurrentLifecycle(generation)) {
        this.restart();
      }
    }, delayMs);
    this.reconnectTimer.unref();
  }

  /** Runs one attempt of the automatic restart now. */
  private restart(): void {
    const request = this.lastRequest;
    if (!request || this.disposed || this.disconnectRequested) {
      return;
    }
    this.startConnect(request, true).catch((error: unknown) => {
      // The retry loop must outlive a broken attempt.
      const message = error instanceof Error ? error.message : String(error);
      this.appendDiagnostic("error", `Xray restart could not be started: ${message}`);
      this.scheduleReconnect(message, this.lifecycleGeneration);
    });
  }

  /**
   * The machine resumed or changed networks: a restart that is waiting out
   * its backoff runs now, because the delay was sized for a failure that has
   * since been overtaken by events.
   */
  wake(reason: string): void {
    if (this.disposed || this.disconnectRequested || !this.lastRequest || !this.reconnectTimer) {
      return;
    }
    this.appendDiagnostic("info", `Wake (${reason}): restarting the Xray transport now instead of waiting out the backoff.`);
    this.clearReconnectTimer();
    this.restart();
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  private cancelProcessStartup(): void {
    this.startupAbortController?.abort();
    this.startupAbortController = undefined;
  }

  /**
   * Stops waiting for a TUN start in flight, for a session the user ended:
   * no further attempt is made, and the start reads as overtaken. The helper
   * still finishes it, and the stop the teardown sends waits behind it.
   */
  private abandonTunStart(): void {
    const abort = this.tunStartAbort;
    this.tunStartAbort = undefined;
    abort?.abort();
  }

  /**
   * Puts the TUN adapter in front of the machine's traffic.
   *
   * Unlike the SSH transport, the helper is pointed straight at Xray's own
   * SOCKS inbound: it speaks `UDP ASSOCIATE`, so a selected application's
   * datagrams - Discord voice, QUIC - are carried rather than dropped, and no
   * listener of ours needs to sit in between.
   *
   * Returns false when the adapter cannot be used, having first taken down an
   * adapter this session still had up.
   */
  private async applyTunRouting(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): Promise<boolean> {
    const dataplane = this.dataplane;
    if (!dataplane || request.tunDataplaneEnabled !== true || process.platform !== "win32") {
      return false;
    }
    // Every way out below that falls back to the proxy path first takes down
    // an adapter this session may still have up: a routing update - or a
    // restart taking held routing over - that cannot restart TUN must not
    // leave the old adapter capturing traffic beneath the system proxy it
    // then applies.
    if (this.tunSuspendedReason) {
      this.appendDiagnostic("warning", `TUN routing is unavailable, continuing on the Windows proxy path: ${this.tunSuspendedReason}.`);
      await this.stopTunRouting();
      return false;
    }

    const availability = await dataplane.probe();
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return false;
    }
    if (!availability.available) {
      this.appendDiagnostic(
        "warning",
        `TUN routing is unavailable, continuing on the Windows proxy path: ${availability.reason ?? "unknown reason"}`
      );
      await this.stopTunRouting();
      return false;
    }

    // Xray opens its own outbound socket, so this process cannot observe the
    // address in use; every address the name resolves to is excluded instead.
    const resolved = await this.protectedAddressResolver(request.profile.host);
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return false;
    }
    // A lookup that comes back empty says nothing about the server while an
    // adapter started for it is still up: the addresses it keeps off itself
    // are what Xray has been reaching it on all along, and they stay.
    const running = this.tunProtectedAddresses;
    const keepRunning = resolved.length === 0 &&
      this.tunRoutingActive &&
      this.dataplane?.isActive === true &&
      running !== undefined &&
      running.host === request.profile.host;
    const protectedAddresses = keepRunning ? running.addresses : resolved;
    if (keepRunning) {
      this.appendDiagnostic(
        "warning",
        `No address could be resolved for ${request.profile.host} just now; the TUN adapter keeps the addresses it was started with (${protectedAddresses.join(", ")}).`
      );
    }
    if (protectedAddresses.length === 0) {
      this.appendDiagnostic(
        "warning",
        `TUN routing is unavailable: no address could be resolved for ${request.profile.host} to keep off the adapter. Continuing on the Windows proxy path.`
      );
      await this.stopTunRouting();
      return false;
    }

    this.tunStartAttempted = true;
    const abort = new AbortController();
    this.tunStartAbort = abort;
    try {
      await startDataplaneWithRetry(dataplane, {
        routingMode: request.routingMode,
        routingRules: request.routingRules,
        routingProxyDomains: request.routingProxyDomains,
        routingDirectDomains: request.routingDirectDomains,
        tunnelProxyEndpoint: `${socksEndpoint.host}:${socksEndpoint.port}`,
        protectedAddresses,
        protectedPort: request.profile.port,
        // With port hopping Xray starts on a random port from the list, not on
        // profile.port, and moves across the rest, so the whole list stays
        // off the adapter.
        ...(request.profile.hopPorts ? { protectedPorts: request.profile.hopPorts } : {}),
        // The addresses above are resolved once, here. A CDN-fronted server
        // that Xray then reaches on another address would be captured and
        // sent back into Xray's own inbound, so its process always goes
        // direct. It is named by its process ID: another program called
        // xray.exe - another client's own core - is routed like any other.
        // Every Xray start applies routing again, so a restarted child's ID
        // reaches the helper too. A helper that predates the field ignores it.
        ...(this.executablePath && this.process?.pid
          ? { directProcesses: [{ pid: this.process.pid, name: path.win32.basename(this.executablePath) }] }
          : {}),
        udpSupported: true,
        enforceIpv6: true,
        adapterName: TUN_ADAPTER_NAME,
        journalPath: this.dataplaneJournalPath
      }, {
        signal: abort.signal,
        onRetry: (attempt, attempts, error) =>
          this.appendDiagnostic(
            "warning",
            `TUN routing did not start on attempt ${attempt} of ${attempts}, retrying: ${errorText(error)}`
          )
      });
    } catch (error) {
      if (abort.signal.aborted || generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
        // Overtaken while it ran: the session was ended, Xray stopped and the
        // hold took routing over, or a newer update is on its way. An adapter still up (the helper
        // keeps the old policy when a new one does not compile) is the hold's
        // to keep - it refuses the selected traffic at Xray's held ports
        // rather than letting it out directly - and the restart, or that
        // update, starts it afresh.
        // Not worded as "TUN routing could not start": that would report
        // TUN as unavailable, and nothing here says it is.
        this.appendDiagnostic("warning", `A routing update was overtaken before it reached the TUN adapter, which is left as it is for the restart or the next update: ${errorText(error)}`);
        return false;
      }
      // Worth spelling out: the fallback still routes domains and IP ranges, so
      // the tunnel looks healthy while process rules quietly stop reaching the
      // applications that ignore the Windows proxy setting.
      this.appendDiagnostic(
        "warning",
        `TUN routing could not start, continuing on the Windows proxy path - process rules will not reach applications that ignore the Windows proxy setting: ${errorText(error)}`
      );
      // The adapter of an earlier start may still be up (the helper keeps the
      // old policy when a new one does not compile), and a start this side
      // gave up on may yet finish in the helper. Either way it comes down
      // before the proxy path goes on top of it.
      await this.stopTunRouting();
      return false;
    } finally {
      if (this.tunStartAbort === abort) {
        this.tunStartAbort = undefined;
      }
    }

    // Our own listener and the Windows proxy setting are both redundant now
    // and would apply the rules a second time on a path the adapter already
    // decided.
    await this.stopLocalProxy();
    try {
      await this.systemProxy.restore();
    } catch (error) {
      this.appendDiagnostic(
        "warning",
        `Windows proxy restore after enabling TUN routing failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    this.tunRoutingActive = true;
    this.tunProtectedAddresses = { host: request.profile.host, addresses: [...protectedAddresses] };
    this.syncDerivedStatus();
    this.localRoutingContext = undefined;
    this.processRoutes.clear();
    this.appendDiagnostic(
      "info",
      "TUN routing is active: every selected application's traffic is captured at the adapter, including UDP. Domain rules match on the name each connection opens (TLS SNI, HTTP Host, QUIC), so a browser that resolved before connecting or uses DNS-over-HTTPS is covered."
    );
    return true;
  }

  private async stopTunRouting(): Promise<void> {
    if (!this.dataplane || (!this.tunRoutingActive && !this.tunStartAttempted)) {
      return;
    }
    this.tunRoutingActive = false;
    this.tunStartAttempted = false;
    this.tunProtectedAddresses = undefined;
    try {
      await this.dataplane.stop();
    } catch (error) {
      this.appendDiagnostic(
        "error",
        `TUN routing teardown failed; the machine may still be routing through a stale adapter: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    this.syncDerivedStatus();
  }

  /**
   * The adapter stopped under the session: its helper died, or found the
   * adapter dead and took itself down. Nothing captures traffic any more, and
   * the Windows proxy setting went when the adapter came up, so selected
   * traffic is already leaving directly while the session still reads
   * Connected. Routing is applied again at once, the ordinary way: a fresh
   * helper brings the adapter back, or the proxy path takes over. While Xray
   * is down that waits for its restart, and apps connect directly until then.
   * Mirrors the SSH transport.
   */
  private handleDataplaneUnexpectedStop(reason: string): void {
    if (this.disposed || (!this.tunRoutingActive && !this.tunStartAttempted)) {
      return;
    }
    this.tunRoutingActive = false;
    this.tunStartAttempted = false;
    this.tunProtectedAddresses = undefined;
    this.syncDerivedStatus();
    const now = Date.now();
    this.tunUnexpectedStops = [
      ...this.tunUnexpectedStops.filter((at) => now - at >= 0 && now - at < TUN_UNEXPECTED_STOP_WINDOW_MS),
      now
    ];
    if (this.tunUnexpectedStops.length >= MAXIMUM_TUN_UNEXPECTED_STOPS) {
      this.tunSuspendedReason = `the TUN adapter stopped unexpectedly ${this.tunUnexpectedStops.length} times within ${Math.round(TUN_UNEXPECTED_STOP_WINDOW_MS / 60_000)} minutes, so it is not restarted again until the next Connect`;
    }
    const trimmedReason = reason.trim();
    const next = this.tunSuspendedReason
      ? "Routing continues on the Windows proxy path for the rest of this session."
      : this.routingHeld
        ? "Routing is applied again when Xray is back: the adapter is restarted, or the Windows proxy path takes over. Until then apps connect directly."
        : "Routing is being applied again: the adapter is restarted, or the Windows proxy path takes over.";
    // The wording is what the attention mapping matches on.
    this.appendDiagnostic(
      "warning",
      `TUN dataplane stopped unexpectedly: ${/[.!?]$/u.test(trimmedReason) ? trimmedReason : `${trimmedReason}.`} ${next}`
    );
    // Queued, so a connect, restart or routing change in progress finishes
    // first; one that started after this point applies routing afresh itself.
    const lifecycleGeneration = this.lifecycleGeneration;
    void this.enqueueMutation(async () => {
      if (this.disposed || !this.isCurrentLifecycle(lifecycleGeneration)) {
        return;
      }
      if (this.routingHeld) {
        // Xray is down as well, and the adapter was what held its routing:
        // there is nothing left to hold. The restart applies routing afresh.
        await this.stopRouting();
        return;
      }
      const request = this.lastRequest;
      const socksEndpoint = this.socksEndpoint;
      if (this.status.state !== "Connected" || !request || !socksEndpoint) {
        return;
      }
      await this.applySystemRouting(request, socksEndpoint);
      // Routing may now be on the proxy path, with local-network rules
      // changed while the adapter carried the traffic.
      this.restartForLocalRuleChange(request);
    }).catch((error: unknown) => {
      this.appendDiagnostic(
        "warning",
        `Applying routing again after the TUN adapter stopped failed: ${error instanceof Error ? error.message : String(error)}`
      );
    });
  }

  private async stopRouting(): Promise<void> {
    this.clearRoutingHold();
    this.heldRoutingEndpoints = [];
    this.stopProcessRoutingMonitor();
    try {
      // The adapter owns the routing table, so it comes down before anything
      // else: leaving capture routes pointing at a dead adapter takes the
      // machine offline.
      await this.stopTunRouting();
      await this.stopLocalProxy();
      this.processRoutes.clear();
      try {
        await this.systemProxy.restore();
      } catch (error) {
        this.appendDiagnostic("warning", `Windows proxy restore failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    } finally {
      // The stopped Xray's ports are let go only now. Until the adapter, the
      // listener and the proxy setting stopped pointing at them, whatever
      // bound them first would have received the flows the hold kept away.
      await this.releaseHeldPorts();
    }
    this.socksEndpoint = undefined;
    this.httpEndpoint = undefined;
    this.syncDerivedStatus();
  }

  private async stopXrayProcess(processHandle: XrayProcess | undefined): Promise<void> {
    try {
      if (processHandle) {
        this.stopParsingProcessLogs(processHandle);
        if (this.process === processHandle) {
          this.process = undefined;
        }
        await terminateProcess(processHandle);
      }
    } catch (error) {
      this.appendDiagnostic("warning", `Xray process cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async cleanupProcessResources(processHandle: XrayProcess | undefined): Promise<void> {
    if (this.process === processHandle) {
      this.process = undefined;
    }
    if (this.routingHeld) {
      // A restart that failed, or one overtaken by a newer failure, leaves the
      // hold in place: its deadline or the next attempt decides. Only what
      // described this attempt's own inbounds goes.
      this.stopProcessRoutingMonitor();
      this.socksEndpoint = undefined;
      this.httpEndpoint = undefined;
      this.syncDerivedStatus();
    } else {
      await this.stopRouting();
    }
    await this.stopXrayProcess(processHandle);
  }

  private appendProcessLogFor(
    processHandle: XrayProcess,
    generation: number,
    level: DiagnosticsEntry["level"],
    chunk: string
  ): boolean {
    if (this.process === processHandle && this.isCurrentLifecycle(generation)) {
      return this.appendProcessLog(level, chunk);
    }
    return false;
  }

  private attachProcessLogging(processHandle: XrayProcess, generation: number): void {
    processHandle.stdout.setEncoding("utf8");
    processHandle.stderr.setEncoding("utf8");
    const stdoutLog = (data: string): void => {
      this.recordStartupFailure(processHandle, data);
      if (!this.appendProcessLogFor(processHandle, generation, "info", data)) {
        this.stopParsingProcessLogs(processHandle);
      }
    };
    const stderrLog = (data: string): void => {
      this.recordStartupFailure(processHandle, data);
      if (!this.appendProcessLogFor(processHandle, generation, "warning", data)) {
        this.stopParsingProcessLogs(processHandle);
      }
    };
    const drainWithoutParsing = (): void => {
      processHandle.stdout.off("data", stdoutLog);
      processHandle.stderr.off("data", stderrLog);
      // Child stdio must remain flowing: pausing an unread pipe can eventually
      // block the Xray process. resume() discards future output in native stream
      // machinery without JS line parsing, UUIDs, IPC or renderer updates.
      processHandle.stdout.resume();
      processHandle.stderr.resume();
    };
    this.processLogDrainers.set(processHandle, drainWithoutParsing);
    processHandle.stdout.on("data", stdoutLog);
    processHandle.stderr.on("data", stderrLog);
  }

  /** Keeps the reason from a "Failed to start" line for the startup error. */
  private recordStartupFailure(processHandle: XrayProcess, chunk: string): void {
    // The cheap test first: this runs for every chunk of connection chatter.
    if (!chunk.includes("Failed to start")) {
      return;
    }
    for (const line of chunk.split(/\r?\n/u)) {
      const reason = xrayStartupFailureReason(line);
      if (reason) {
        this.processStartupFailures.set(processHandle, reason);
      }
    }
  }

  /**
   * The message for a startup that did not reach its listeners. When Xray
   * exited, its output gets a moment to drain first, so the reason it printed
   * can be named instead of only the exit code.
   */
  private async describeStartupFailure(processHandle: XrayProcess, error: unknown, outputClosed: Promise<void>): Promise<string> {
    const message = error instanceof Error ? error.message : String(error);
    if (processHandle.exitCode === null && processHandle.signalCode === null) {
      return message;
    }
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      outputClosed,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, XRAY_STARTUP_OUTPUT_DRAIN_MS);
        timer.unref();
      })
    ]);
    clearTimeout(timer);
    const reason = this.processStartupFailures.get(processHandle);
    return reason ? `${message.replace(/\.$/u, "")}: ${reason}` : message;
  }

  private stopParsingProcessLogs(processHandle: XrayProcess): void {
    const drain = this.processLogDrainers.get(processHandle);
    if (!drain) {
      return;
    }
    this.processLogDrainers.delete(processHandle);
    drain();
  }

  private enqueueMutation(operation: () => Promise<void>): Promise<void> {
    const result = this.mutationTail.then(operation, operation);
    this.mutationTail = result.catch(() => undefined);
    return result;
  }

  private isCurrentLifecycle(generation: number): boolean {
    return generation === this.lifecycleGeneration;
  }

  private isCurrentMutation(lifecycleGeneration: number, routingGeneration: number): boolean {
    return !this.disposed && this.isCurrentLifecycle(lifecycleGeneration) && routingGeneration === this.routingGeneration;
  }

  private async applySystemRouting(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): Promise<void> {
    this.stopProcessRoutingMonitor();
    const generation = this.processRoutingGeneration;
    const httpEndpoint = this.httpEndpoint ?? socksEndpoint;
    const summary = new RoutingMatcher(request.routingMode, request.routingRules).summary();
    const hasProcessRouting = supportsDynamicProcessRouting(request.routingMode, request.routingRules);

    // Process rules can only be honoured where the owning process is known, so
    // when the native helper can attribute connections we place our own
    // listener in front of Xray and decide there.
    const context: LocalRoutingContext = {
      routingMode: request.routingMode,
      routingRules: request.routingRules,
      routingProxyDomains: request.routingProxyDomains,
      routingDirectDomains: request.routingDirectDomains,
      // The SSH transport has always excluded its own server here. Xray did
      // not, so a rule broad enough to cover the profile's own host - a
      // `process.name` rule above all, which routes everything an application
      // sends - handed that connection back to Xray's inbound and asked it to
      // dial itself through itself.
      protectedEndpoint: { host: request.profile.host, port: request.profile.port }
    };
    // The adapter is tried first: it is the only path that holds a
    // `process.name` rule against an application that ignores the Windows
    // proxy setting, and the only one that can carry that application's UDP.
    if (await this.applyTunRouting(request, socksEndpoint, generation)) {
      return;
    }

    const enforceability = await this.localRoutingEnforcer.describeEnforceability(context);
    // Checked before either fallback, as the SSH transport does: an adapter
    // attempt that lost to a newer routing change - or to Xray stopping, whose
    // hold keeps what is in place - must not put the proxy path on top.
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }
    if (enforceability.enforceable) {
      await this.applyLocallyEnforcedRouting(request, socksEndpoint, context, generation, summary);
      return;
    }
    if (enforceability.reason && hasProcessRouting) {
      // Naming the cause matters because the tunnel keeps working: domain and
      // IP rules are unaffected, so the only visible symptom is that selected
      // applications quietly stop being selected.
      this.appendDiagnostic(
        "warning",
        `Per-process enforcement is unavailable, so process rules fall back to PAC guessing - ${enforceability.reason}.`
      );
    }
    await this.stopLocalProxy();

    let literalIpSnapshotResult: SystemProxyApplyResult | undefined;
    let literalIpSnapshotError: unknown;
    let literalIpSnapshotFailed = false;
    let literalIpSnapshotSignature: string | undefined;
    if (hasProcessRouting) {
      await this.learnProcessRoutingIps(
        request.routingRules,
        request.routingDirectDomains,
        generation,
        async (signature) => {
          literalIpSnapshotSignature = signature;
          try {
            literalIpSnapshotResult = await this.publishProcessRoutingSnapshot(
              request,
              socksEndpoint,
              generation,
              signature
            );
          } catch (error) {
            literalIpSnapshotFailed = true;
            literalIpSnapshotError = error;
            this.processRoutes.applyPending = true;
          }
        }
      );
      if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
        return;
      }
      this.appendDiagnostic(
        "warning",
        "Selected process-name routing is using dynamic process destination PAC rules. Reviewed host families stay stable while DNS-learned exact names use a bounded TTL; already-open sockets may still need reconnect, and strict per-process enforcement requires WFP/TUN."
      );
      if (
        literalIpSnapshotFailed &&
        literalIpSnapshotSignature === this.processRoutes.lastSignature
      ) {
        if (this.status.state === "Connected") {
          this.startProcessRoutingMonitor(request, socksEndpoint);
        }
        throw literalIpSnapshotError;
      }
    } else {
      this.processRoutes.clear();
    }
    this.processRoutes.applyPending = hasProcessRouting;
    let result: SystemProxyApplyResult;
    if (
      hasProcessRouting &&
      literalIpSnapshotResult &&
      literalIpSnapshotSignature === this.processRoutes.lastSignature
    ) {
      result = literalIpSnapshotResult;
    } else {
      try {
        result = await this.systemProxy.apply({
          mode: request.routingMode,
          rules: buildSelectedRulesWithProcessIps(
            request.routingRules,
            this.processRoutes.currentIps(),
            this.processRoutes.currentDomains()
          ),
          proxyDomains: request.routingProxyDomains,
          directDomains: request.routingDirectDomains,
          socksHost: httpEndpoint.host,
          socksPort: httpEndpoint.port,
          proxyProtocol: "http",
          forcePacEndpointRotation: hasProcessRouting
        });
      } catch (error) {
        if (hasProcessRouting && generation === this.processRoutingGeneration && this.status.state === "Connected") {
          this.startProcessRoutingMonitor(request, socksEndpoint);
        }
        throw error;
      }
    }
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }
    if (hasProcessRouting && result.applied) {
      this.processRoutes.appliedSignature = this.processRoutes.lastSignature;
      this.processRoutes.applyPending = false;
    }
    this.appendDiagnostic(result.applied ? "info" : "warning", result.message);
    if (hasProcessRouting) {
      this.startProcessRoutingMonitor(request, socksEndpoint);
    }

    if (request.routingMode === "proxy-all") {
      this.appendDiagnostic("info", "Proxy-all TCP routing uses the local Xray HTTP proxy through the Windows system proxy when running on Windows.");
      return;
    }
    this.appendDiagnostic(
      summary.enabledRules > 0 ? "info" : "warning",
      `Selected routing prepared for Xray transport: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}, matchedProcessConnections=${this.processRoutes.lastMatchedConnections}, learnedProcessIps=${this.processRoutes.ips.size}, learnedProcessDomains=${this.processRoutes.currentDomains().size}.`
    );
  }

  /**
   * Routes all proxy-aware TCP through our own listener, which then evaluates
   * domain, IP and process rules per connection and forwards only matching
   * traffic into Xray's SOCKS inbound. Everything else leaves the machine
   * directly, so unselected applications are untouched.
   */
  private async applyLocallyEnforcedRouting(
    request: ProxyConnectRequest,
    xraySocksEndpoint: { host: string; port: number },
    context: LocalRoutingContext,
    generation: number,
    summary: RoutingMatcherSummary
  ): Promise<void> {
    this.processRoutes.clear();
    const endpoint = await this.startLocalProxy(xraySocksEndpoint, context);
    if (!endpoint || generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }

    // The direct list is deliberately withheld from the PAC here: the PAC runs
    // before the listener and cannot see processes, so a direct-list entry
    // there would carve holes in a selected application's traffic. It is
    // applied per connection instead, after the process rule.
    const result = await this.systemProxy.apply({
      mode: "proxy-all",
      rules: request.routingRules,
      proxyDomains: request.routingProxyDomains,
      directDomains: [],
      socksHost: endpoint.host,
      socksPort: endpoint.port
    });
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }
    this.appendDiagnostic(result.applied ? "info" : "warning", result.message);
    this.appendDiagnostic(
      "info",
      `Selected routing is enforced locally with native process attribution: enabled=${summary.enabledRules}, domains=${summary.domainRules}, ips=${summary.ipRules}, processes=${summary.processRules}. Matching traffic is forwarded into Xray; unmatched traffic leaves the machine directly.`
    );
  }

  /**
   * Points the local routing listener at Xray with these rules, starting the
   * listener only when none is running. A routing edit, or Xray coming back on
   * other ports after a restart, changes what the listener decides and where
   * it forwards, not the listener itself, so both are swapped in place - as
   * the SSH transport swaps its context. Rebuilding the listener instead
   * destroyed every open connection, direct ones included, on each rule
   * toggle.
   */
  private async startLocalProxy(
    xraySocksEndpoint: { host: string; port: number },
    context: LocalRoutingContext
  ): Promise<{ host: string; port: number } | undefined> {
    // Published before a listener can accept anything: a connection accepted
    // without a context cannot be attributed and would bypass the rules.
    this.localRoutingUpstream = xraySocksEndpoint;
    this.localRoutingContext = context;
    if (this.localProxy && this.localProxyEndpoint) {
      return this.localProxyEndpoint;
    }
    const proxy = new Socks5Proxy({
      listenHost: "127.0.0.1",
      // Shared with the SSH transport, so switching between the two keeps the
      // same local endpoint for clients that cannot follow the system proxy.
      preferredListenPort: preferredLocalProxyPort(),
      // Both read per connection, so a swap applies from the next one on.
      connectChannel: async (target, originator, signal) => {
        const upstream = this.localRoutingUpstream;
        if (!upstream) {
          throw new Error("Xray transport is not connected.");
        }
        const openUpstreamChannel = (): ReturnType<typeof openSocks5UpstreamChannel> =>
          openSocks5UpstreamChannel(upstream, target, { signal });
        const context = this.localRoutingContext;
        if (!context) {
          return openUpstreamChannel();
        }
        const { channel, decision } = await this.localRoutingEnforcer.openChannel(
          context,
          target,
          originator,
          openUpstreamChannel,
          signal
        );
        this.routingDecisions.record(target, decision);
        return channel;
      }
    });
    // Claimed before it starts, so a warning from start() - a remembered port
    // that is taken - is reported as this listener's.
    this.localProxy = proxy;
    proxy.onEvent((event) => {
      if (this.localProxy !== proxy) {
        return;
      }
      if (event.type === "error") {
        this.appendBoundedProxyDiagnostic("warning", event.message);
      }
    });
    try {
      const endpoint = await proxy.start();
      rememberLocalProxyPort(endpoint.port);
      this.localProxyEndpoint = endpoint;
      this.startLocalProxyHeartbeat(proxy);
      this.appendDiagnostic("info", `Local routing proxy is listening on ${endpoint.host}:${endpoint.port}.`);
      return endpoint;
    } catch (error) {
      if (this.localProxy === proxy) {
        this.localProxy = undefined;
        this.localRoutingContext = undefined;
        this.localRoutingUpstream = undefined;
      }
      await proxy.stop().catch(() => undefined);
      this.appendDiagnostic(
        "warning",
        `Local routing proxy failed to start: ${error instanceof Error ? error.message : String(error)}`
      );
      return undefined;
    }
  }

  private async stopLocalProxy(): Promise<void> {
    this.stopLocalProxyHeartbeat();
    const proxy = this.localProxy;
    this.localProxy = undefined;
    this.localProxyEndpoint = undefined;
    this.localRoutingContext = undefined;
    this.localRoutingUpstream = undefined;
    await proxy?.stop().catch(() => undefined);
  }

  /**
   * Logs a periodic summary of local-proxy traffic while the tunnel is up, so a
   * data-plane stall can be told apart from a routing miss without a live
   * debugger on the user's machine. It belongs to the listener, which outlives
   * routing edits, rather than to a routing generation.
   */
  private startLocalProxyHeartbeat(proxy: Socks5Proxy): void {
    this.stopLocalProxyHeartbeat();
    const heartbeat = new ProxyActivityHeartbeat(
      () => (this.localProxy === proxy ? proxy.snapshotStats() : undefined),
      (message) => {
        if (this.localProxy === proxy && this.isRoutingApplicable()) {
          this.appendDiagnostic("info", message);
        }
      }
    );
    heartbeat.start();
    this.localProxyHeartbeat = setInterval(() => heartbeat.tick(), PROXY_HEARTBEAT_INTERVAL_MS);
    this.localProxyHeartbeat.unref();
  }

  private stopLocalProxyHeartbeat(): void {
    if (this.localProxyHeartbeat) {
      clearInterval(this.localProxyHeartbeat);
      this.localProxyHeartbeat = undefined;
    }
  }

  private startProcessRoutingMonitor(request: ProxyConnectRequest, socksEndpoint: { host: string; port: number }): void {
    this.stopProcessRoutingMonitor();
    if (!supportsDynamicProcessRouting(request.routingMode, request.routingRules)) {
      return;
    }

    const generation = this.processRoutingGeneration;
    this.processRoutes.beginDiscovery();
    this.scheduleProcessRoutingRefresh(request, socksEndpoint, generation);
  }

  private scheduleProcessRoutingRefresh(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): void {
    if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
      return;
    }
    this.processRoutingMonitor = setTimeout(() => {
      this.processRoutingMonitor = undefined;
      if (generation !== this.processRoutingGeneration || !this.isRoutingApplicable()) {
        return;
      }
      void this.enqueueMutation(() => this.refreshProcessRouting(request, socksEndpoint, generation))
        .catch((error: unknown) => {
          if (!this.processRoutes.warningEmitted) {
            this.processRoutes.warningEmitted = true;
            this.appendDiagnostic(
              "warning",
              `Process-name routing refresh failed for Xray transport: ${error instanceof Error ? error.message : String(error)}`
            );
          }
        })
        .finally(() => {
          this.scheduleProcessRoutingRefresh(request, socksEndpoint, generation);
        });
    }, this.processRoutes.nextRefreshIntervalMs());
    this.processRoutingMonitor.unref();
  }

  private stopProcessRoutingMonitor(): void {
    this.processRoutingGeneration += 1;
    if (!this.processRoutingMonitor) {
      return;
    }
    clearTimeout(this.processRoutingMonitor);
    this.processRoutingMonitor = undefined;
  }

  private async refreshProcessRouting(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number
  ): Promise<void> {
    if (generation !== this.processRoutingGeneration || this.status.state !== "Connected") {
      return;
    }
    let literalIpSnapshotResult: SystemProxyApplyResult | undefined;
    let literalIpSnapshotError: unknown;
    let literalIpSnapshotFailed = false;
    let literalIpSnapshotSignature: string | undefined;
    await this.learnProcessRoutingIps(
      request.routingRules,
      request.routingDirectDomains,
      generation,
      async (signature) => {
        literalIpSnapshotSignature = signature;
        try {
          literalIpSnapshotResult = await this.publishProcessRoutingSnapshot(
            request,
            socksEndpoint,
            generation,
            signature
          );
        } catch (error) {
          literalIpSnapshotFailed = true;
          literalIpSnapshotError = error;
          this.processRoutes.applyPending = true;
        }
      }
    );
    if (
      literalIpSnapshotFailed &&
      literalIpSnapshotSignature === this.processRoutes.lastSignature
    ) {
      throw literalIpSnapshotError;
    }
    if (generation !== this.processRoutingGeneration || this.status.state !== "Connected") {
      return;
    }
    if (
      literalIpSnapshotResult &&
      literalIpSnapshotSignature === this.processRoutes.lastSignature
    ) {
      this.appendDiagnostic(
        literalIpSnapshotResult.applied ? "info" : "warning",
        `Process-name literal-IP routing updated before DNS enrichment for Xray transport: matchedProcessConnections=${this.processRoutes.lastMatchedConnections}, learnedProcessIps=${this.processRoutes.ips.size}. ${literalIpSnapshotResult.message}`
      );
      return;
    }
    if (!this.processRoutes.applyPending && this.processRoutes.lastSignature === this.processRoutes.appliedSignature) {
      return;
    }

    const observedSignature = this.processRoutes.lastSignature;
    const result = await this.publishProcessRoutingSnapshot(
      request,
      socksEndpoint,
      generation,
      observedSignature
    );
    if (!result) {
      return;
    }
    this.appendDiagnostic(
      result.applied ? "info" : "warning",
      `Process-name routing updated for Xray transport: matchedProcessConnections=${this.processRoutes.lastMatchedConnections}, learnedProcessIps=${this.processRoutes.ips.size}, learnedProcessDomains=${this.processRoutes.currentDomains().size}. ${result.message}`
    );
  }

  private async publishProcessRoutingSnapshot(
    request: ProxyConnectRequest,
    socksEndpoint: { host: string; port: number },
    generation: number,
    signature: string
  ): Promise<SystemProxyApplyResult | undefined> {
    if (
      generation !== this.processRoutingGeneration ||
      !this.isRoutingApplicable() ||
      signature !== this.processRoutes.lastSignature
    ) {
      return undefined;
    }
    this.processRoutes.applyPending = true;
    const endpoint = this.httpEndpoint ?? socksEndpoint;
    const result = await this.systemProxy.apply({
      mode: request.routingMode,
      rules: buildSelectedRulesWithProcessIps(
        request.routingRules,
        this.processRoutes.currentIps(),
        this.processRoutes.currentDomains()
      ),
      proxyDomains: request.routingProxyDomains,
      directDomains: request.routingDirectDomains,
      socksHost: endpoint.host,
      socksPort: endpoint.port,
      proxyProtocol: "http",
      forcePacEndpointRotation: true
    });
    if (
      result.applied &&
      generation === this.processRoutingGeneration &&
      this.isRoutingApplicable() &&
      this.processRoutes.lastSignature === signature
    ) {
      this.processRoutes.appliedSignature = signature;
      this.processRoutes.applyPending = false;
    }
    return result;
  }

  private learnProcessRoutingIps(
    rules: RoutingRule[],
    directDomains: string[] = [],
    generation?: number,
    publishLiteralIpSnapshot?: (signature: string) => Promise<void>
  ): Promise<boolean> {
    return this.processRoutes.learn(
      rules,
      directDomains,
      () => generation !== undefined && generation !== this.processRoutingGeneration,
      publishLiteralIpSnapshot
    );
  }

  private setStatus(update: Partial<RuntimeStatus>): void {
    this.status = {
      ...this.status,
      ...update,
      ...this.derivedStatus(),
      transport: "xray",
      platformTarget: this.status.platformTarget
    };
    this.emit({ type: "status-changed", status: this.getStatus() });
  }

  /** Status fields that follow Xray's inbounds and the adapter rather than the session state. */
  private derivedStatus(): Pick<RuntimeStatus, "localProxy" | "tunActive"> {
    const http = this.httpEndpoint;
    const socks = this.socksEndpoint;
    return {
      // Xray's own inbounds: what an app on macOS or Linux is pointed at.
      localProxy: http && socks ? { host: http.host, httpPort: http.port, socksPort: socks.port } : undefined,
      tunActive: this.tunRoutingActive && this.dataplane?.isActive === true
    };
  }

  /** Publishes an inbound or adapter change that happened without a state change. */
  private syncDerivedStatus(): void {
    const derived = this.derivedStatus();
    if (!sameLocalProxy(derived.localProxy, this.status.localProxy) || derived.tunActive !== this.status.tunActive) {
      this.setStatus({});
    }
  }

  private appendProcessLog(streamLevel: DiagnosticsEntry["level"], chunk: string): boolean {
    if (this.importantProcessLogLines >= MAX_XRAY_IMPORTANT_LOG_LINES) {
      return false;
    }
    const boundedChunk = chunk.length > MAX_XRAY_PROCESS_LOG_CHUNK_CHARACTERS
      ? chunk.slice(0, MAX_XRAY_PROCESS_LOG_CHUNK_CHARACTERS)
      : chunk;
    for (const entry of boundedChunk.split(/\r?\n/u)) {
      const line = entry.trim();
      if (!line) {
        continue;
      }
      const level = classifyXrayLogLevel(line, streamLevel);
      if (level === "info") {
        if (this.routineProcessLogLines >= MAX_XRAY_ROUTINE_LOG_LINES) {
          continue;
        }
        this.routineProcessLogLines += 1;
        if (this.routineProcessLogLines === MAX_XRAY_ROUTINE_LOG_LINES) {
          this.appendDiagnostic(
            "info",
            "Further Xray connection notices are suppressed for this session. Warnings and errors are still recorded."
          );
          continue;
        }
      } else {
        this.importantProcessLogLines += 1;
        if (this.importantProcessLogLines === MAX_XRAY_IMPORTANT_LOG_LINES) {
          this.appendDiagnostic("warning", "Further Xray warnings are suppressed for this session.");
          return false;
        }
      }
      const boundedLine = line.length > MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS
        ? `${line.slice(0, MAX_XRAY_PROCESS_LOG_LINE_CHARACTERS)}…`
        : line;
      this.appendDiagnostic(level, `Xray: ${boundedLine}`);
    }
    return true;
  }

  /**
   * Per-connection routing decisions are useful for diagnosing a rule, but a
   * busy browser opens hundreds of sockets, so the stream is capped.
   */
  private appendBoundedProxyDiagnostic(level: DiagnosticsEntry["level"], message: string): void {
    if (this.proxyDiagnostics >= MAX_LOCAL_PROXY_DIAGNOSTICS) {
      return;
    }
    this.proxyDiagnostics += 1;
    if (this.proxyDiagnostics === MAX_LOCAL_PROXY_DIAGNOSTICS) {
      this.appendDiagnostic("info", "Further local routing diagnostics are suppressed for this session.");
      return;
    }
    this.appendDiagnostic(level, message);
  }

  private appendDiagnostic(level: DiagnosticsEntry["level"], message: string): void {
    this.emit({
      type: "diagnostics-appended",
      entry: {
        id: randomUUID(),
        at: new Date().toISOString(),
        level,
        message: redactSecrets(message)
      }
    });
  }

  private emitError(message: string): void {
    this.emit({ type: "error", message: redactSecrets(message) });
  }

  private emit(event: ServiceEvent): void {
    this.events.emit("event", event);
  }

  private isRoutingApplicable(): boolean {
    return this.status.state === "Connecting" || this.status.state === "Connected";
  }
}

/**
 * Removes the config file earlier versions passed to Xray, and the temporary
 * files they wrote it through. Never throws: a folder that does not exist has
 * nothing to sweep.
 */
export async function sweepLegacyRuntimeConfigs(runtimeDirectory: string): Promise<void> {
  let names: string[];
  try {
    names = await readdir(runtimeDirectory);
  } catch {
    return;
  }
  const stale = names.filter((name) =>
    name === LEGACY_RUNTIME_CONFIG_FILE ||
    (name.startsWith(`${LEGACY_RUNTIME_CONFIG_FILE}.`) && name.endsWith(".tmp"))
  );
  await Promise.all(stale.map((name) => rm(path.join(runtimeDirectory, name), { force: true }).catch(() => undefined)));
}

/** "Hysteria 2 example.com:443,20000-30000": the protocol and every port the profile may dial. */
/**
 * Whether a restart failed in a way only the user can fix: the runtime or the
 * config, as opposed to a port race, a slow start or a proxy that would not
 * apply. Xray reports a config it refuses under infra/conf.
 */
function isBlockedRestart(error: unknown): boolean {
  if (error instanceof XrayRestartBlockedError) {
    return true;
  }
  const message = error instanceof Error ? error.message : String(error);
  return /\binfra\/conf\b|failed to (?:load|parse) config/iu.test(message);
}

/**
 * The user's rules for the local network that Xray's config carries, or
 * undefined where it keeps no local network direct at all: only the Windows
 * proxy hands Xray system traffic, and elsewhere everything sent to it was
 * sent there by hand (see XrayConfigInput.localNetworkDirect).
 */
function localRuleOverridesFor(rules: ProxyConnectRequest["routingRules"]): XrayLocalRuleOverrides | undefined {
  return process.platform === "win32" ? xrayLocalRuleOverrides(rules) : undefined;
}

/**
 * Binds each endpoint so nothing else can, and turns away every connection
 * made to it. All or nothing: a port that cannot be bound releases the rest
 * and rejects.
 */
export async function bindRefusingLoopbackPorts(endpoints: ReadonlyArray<{ host: string; port: number }>): Promise<HeldInboundPorts> {
  const servers: net.Server[] = [];
  const release = async (): Promise<void> => {
    await Promise.all(
      servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))
    );
  };
  try {
    for (const endpoint of endpoints) {
      const server = net.createServer((socket) => socket.destroy());
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen({ host: endpoint.host, port: endpoint.port, exclusive: true }, () => {
          server.off("error", reject);
          resolve();
        });
      });
      servers.push(server);
    }
  } catch (error) {
    await release();
    throw error;
  }
  return { release };
}

function describeProfileEndpoint(profile: ProxyProfile): string {
  return `${proxyProtocolLabel(profile.protocol)} ${profile.host}:${profile.hopPorts ?? profile.port}`;
}

/**
 * Whether a Hysteria 2 link asks for insecure=1 without a pinSHA256 pin. Xray
 * removed tlsSettings.allowInsecure, so the flag is dropped and the server's
 * certificate is verified anyway: fine for a real certificate, fatal for a
 * self-signed one that only a pin could have accepted.
 */
function hasUnpinnedInsecureFlag(request: ProxyConnectRequest): boolean {
  if (request.profile.protocol !== "hysteria2") {
    return false;
  }
  try {
    const link = parseHysteria2Link(request.secrets.rawUri);
    return link.insecure && link.pinnedCertSha256.length === 0;
  } catch {
    // Building the config reports a link that cannot be read.
    return false;
  }
}

/**
 * Masks credentials in a line bound for the log or the status. Beyond the
 * `key=value` forms, Xray echoes config fragments as JSON ("auth", a
 * salamander "password") and a share link carries its credential in the
 * userinfo. A pinSHA256 is a public certificate hash and is left alone.
 *
 * Every line Xray prints passes through here, so each pattern must stay
 * linear in the line's length. The share-link one finds the "://" and looks
 * back a single character for a scheme, instead of matching the scheme
 * forwards: `\b[a-z][a-z0-9+.-]*:\/\/` restarted at every label of a long
 * dotted host and rescanned the rest of it each time, a full second for one
 * 64 KB line. It also never misses a scheme for being long, and at worst
 * masks an "x://y@" that no scheme precedes.
 */
export function redactSecrets(message: string): string {
  return message
    .replace(/"((?:[\w-]*password)|auth)"\s*:\s*"(?:[^"\\]|\\.)*"/giu, "\"$1\":\"<redacted>\"")
    .replace(/(?<=[a-z0-9+.-]:\/\/)[^\s/?#@]+@/giu, "<redacted>@")
    .replace(/(password|passphrase|private key|proxy uri|uri)\s*[:=]\s*\S+/giu, "$1=<redacted>");
}

/**
 * The reason in Xray's "Failed to start: ..." line, without the boilerplate
 * naming the config file: "infra/conf: failed to build outbound config ...".
 * Redacted, and cut from the front when long, because the most specific
 * cause comes last in Xray's error chains.
 */
export function xrayStartupFailureReason(line: string): string | undefined {
  const trimmed = line.trim();
  if (!XRAY_STARTUP_FAILURE_PREFIX.test(trimmed)) {
    return undefined;
  }
  const reason = redactSecrets(
    trimmed
      .replace(XRAY_STARTUP_FAILURE_PREFIX, "")
      .replace(/^main: failed to load config files: \[[^\]]*\]\s*>\s*/u, "")
  ).trim();
  if (!reason) {
    return undefined;
  }
  return reason.length > MAX_XRAY_STARTUP_REASON_CHARACTERS
    ? `…${reason.slice(-MAX_XRAY_STARTUP_REASON_CHARACTERS)}`
    : reason;
}

/**
 * Reads Xray's own severity marker, which is what separates a connection
 * notice from the failure that explains it. Xray writes both to stdout, so the
 * stream a line arrived on says nothing useful on its own.
 */
export function classifyXrayLogLevel(
  line: string,
  streamLevel: DiagnosticsEntry["level"]
): DiagnosticsEntry["level"] {
  // A config Xray refuses gets no marker at all, only this prefix.
  if (/\[Error\]/u.test(line) || XRAY_STARTUP_FAILURE_PREFIX.test(line.trim())) {
    return "error";
  }
  if (/\[Warning\]/u.test(line)) {
    return "warning";
  }
  if (/\[Info\]|\[Debug\]/u.test(line)) {
    return "info";
  }
  return streamLevel;
}
