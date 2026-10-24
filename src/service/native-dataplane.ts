import { NativeHelperClient } from "./native-helper-client.js";
import { WINTUN_SEARCH_DIRECTORIES_ENV, wintunSearchDirectories } from "./tun-routing.js";
import type { DataplaneStartRequest } from "./local-ipc-protocol.js";
import type { ServiceEvent } from "../shared/ipc.js";

/**
 * Drives the native TUN dataplane.
 *
 * The Windows user proxy is advisory and TCP-only: an application has to read
 * it and choose to obey it. Telegram, Discord and anything with its own proxy
 * stack or a QUIC socket simply do not, which is why a `process.name` rule can
 * hold on that path and the application's traffic still leaves directly. A TUN
 * adapter owns the routes instead, so the OS hands over the packets regardless
 * of what the application intended.
 *
 * The adapter and the routing table both need administrator rights, and this
 * app ships a portable executable with no installer to carry them. The helper
 * therefore reports `tunDevice` only when it is actually elevated, and this
 * controller reads that answer before the transport commits to a routing path.
 */
export interface NativeDataplaneOptions {
  executablePath: string;
  onDiagnostic?: (level: "info" | "warning" | "error", message: string) => void;
  /**
   * The application's own data folder. Included in the helper's search for
   * `wintun.dll`, because it is somewhere a user can reliably put a file - the
   * packaged resources folder of a portable build is not.
   */
  userDataDirectory?: string;
  /**
   * Called whenever the adapter starts or stops carrying traffic, including
   * when the helper dies under it, so the status shown to the user follows.
   */
  onActiveChange?: (active: boolean) => void;
}

/**
 * The surface the transports use, so a test can drive routing decisions
 * without an elevated helper.
 */
export interface DataplaneController {
  readonly isActive: boolean;
  probe(): Promise<DataplaneAvailability>;
  /**
   * `signal` gives up waiting for the helper's answer; a stop is owed for the
   * start all the same (see {@link NativeDataplaneController.stop}).
   */
  start(request: DataplaneStartRequest, signal?: AbortSignal): Promise<void>;
  stop(): Promise<void>;
  dispose(): Promise<void>;
  /**
   * Tells `listener` when a dataplane that was carrying traffic stopped
   * without being asked to: its helper exited, or reported the adapter dead
   * and took itself down. Nothing captures traffic any more at that point, so
   * a transport that relied on the adapter must route some other way at
   * once. Returns the unsubscribe.
   *
   * While anyone listens, the listener owns reporting the stop; with nobody
   * listening the controller reports it as an error diagnostic itself.
   */
  onUnexpectedStop?(listener: (reason: string) => void): () => void;
}

export interface DataplaneAvailability {
  available: boolean;
  /** Why the dataplane cannot be used, for a diagnostic the user can act on. */
  reason?: string;
}

/**
 * How long a helper that holds nothing any more may take to exit once its
 * input is closed. It exits as soon as it reads the end of its input.
 */
const IDLE_HELPER_EXIT_GRACE_MS = 2_000;
/**
 * How long a helper whose last stop did not complete may keep running after
 * its input is closed. Reading the end of its input makes it tear down what
 * it still holds; killing it straight away is what used to cut a routing
 * rollback short and leave capture routes behind.
 */
const TEARDOWN_HELPER_EXIT_GRACE_MS = 30_000;

/** The stderr prefix of the one line a helper writes before it exits because its dataplane failed. */
const FATAL_STDERR_PREFIX = "dataplane fatal:";
/** The exit status of a helper whose dataplane failed on its own. */
const DATAPLANE_FATAL_EXIT_CODE = 3;

export class NativeDataplaneController implements DataplaneController {
  private client: NativeHelperClient | undefined;
  private connecting: Promise<NativeHelperClient> | undefined;
  /** Bumped per spawned helper, so what a replaced one reports late is told apart. */
  private helperGeneration = 0;
  /** The generation of `client`. */
  private clientGeneration = 0;
  /** The generation of the helper running the active dataplane. */
  private dataplaneGeneration = 0;
  private starting: Promise<void> | undefined;
  private stopping: Promise<void> | undefined;
  private active = false;
  /**
   * A start was sent and no stop has completed since. A start the helper
   * finishes after this side stopped waiting for it brings an adapter up that
   * `active` never learns about; a stop is still owed for it.
   */
  private startAttempted = false;
  private disposed = false;
  /** Why a helper said its dataplane failed, from the line it wrote before exiting. */
  private fatalLine: { generation: number; reason: string } | undefined;
  private readonly unexpectedStopListeners = new Set<(reason: string) => void>();

  constructor(private readonly options: NativeDataplaneOptions) {}

  /** True while an adapter is up and carrying traffic. */
  get isActive(): boolean {
    return this.active;
  }

  onUnexpectedStop(listener: (reason: string) => void): () => void {
    this.unexpectedStopListeners.add(listener);
    return () => {
      this.unexpectedStopListeners.delete(listener);
    };
  }

  /**
   * Reports whether the helper can create an adapter right now.
   *
   * The answer must be settled before the transport applies any routing:
   * choosing the TUN path and then failing to bring it up would leave the
   * machine with neither interception in place.
   */
  async probe(): Promise<DataplaneAvailability> {
    if (this.disposed) {
      return { available: false, reason: "The dataplane controller is disposed." };
    }
    let client: NativeHelperClient;
    try {
      client = await this.withCurrentCapabilities();
    } catch (error) {
      return { available: false, reason: errorMessage(error) };
    }
    const capabilities = client.handshake?.capabilities;
    if (!capabilities?.tunDevice || !capabilities.routeManipulation) {
      // The helper knows exactly which prerequisite is missing; repeating a
      // generic "start as administrator" here sent a user who had already done
      // that chasing the wrong thing for days.
      const reason = capabilities?.tunUnavailableReason?.trim();
      return {
        available: false,
        reason: reason
          ? `The native helper cannot create a tunnel adapter: ${reason}.`
          : "The native helper cannot create a tunnel adapter. It needs wintun.dll beside the service binary and an elevated process."
      };
    }
    return { available: true };
  }

  /**
   * Brings the dataplane up, or swaps the routing policy of a running one.
   *
   * Concurrent calls are serialised: a routing change arriving while the
   * adapter is still coming up must not start a second one.
   */
  async start(request: DataplaneStartRequest, signal?: AbortSignal): Promise<void> {
    if (this.disposed) {
      throw new Error("The dataplane controller is disposed.");
    }
    const started = (this.starting ?? Promise.resolve()).catch(() => undefined).then(async () => {
      if (signal?.aborted) {
        throw new Error("The TUN dataplane start was abandoned.");
      }
      const client = await this.connect();
      const generation = this.clientGeneration;
      this.startAttempted = true;
      await client.startDataplane(request, signal);
      this.dataplaneGeneration = generation;
      this.setActive(true);
    });
    this.starting = started.catch(() => undefined);
    await started;
  }

  /**
   * Takes the dataplane down and restores routing. Safe to call when idle.
   *
   * A stop is sent whenever a start was, even one that failed here: a start
   * this side gave up waiting for may still have succeeded in the helper,
   * which serves one command at a time and would otherwise keep an adapter
   * capturing traffic toward a listener that is gone. A second call while a
   * stop is running joins it.
   */
  async stop(): Promise<void> {
    if (this.stopping) {
      return this.stopping;
    }
    const client = this.client;
    if (!client?.running || (!this.active && !this.startAttempted)) {
      this.startAttempted = false;
      this.setActive(false);
      return;
    }
    const stopping = (async () => {
      try {
        await client.stopDataplane();
        this.startAttempted = false;
      } finally {
        this.setActive(false);
      }
    })();
    this.stopping = stopping;
    try {
      await stopping;
    } finally {
      if (this.stopping === stopping) {
        this.stopping = undefined;
      }
    }
  }

  private setActive(active: boolean): void {
    if (this.active === active) {
      return;
    }
    this.active = active;
    this.options.onActiveChange?.(active);
  }

  /**
   * Stops the dataplane and releases the helper.
   *
   * The stop is attempted first - or, when one is already running, waited
   * for within its own deadline - and its failure is reported rather than
   * swallowed. The helper is then let go gently: its input is closed, which
   * makes it tear down whatever it still holds, and it is killed only if it
   * has not exited by itself in time. Killing it with capture routes still
   * installed would leave the machine unable to reach the network.
   */
  async dispose(): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    let stopped = true;
    try {
      await this.stop();
    } catch (error) {
      stopped = false;
      this.options.onDiagnostic?.("error", "TUN dataplane did not stop cleanly: " + errorMessage(error));
    }
    const client = this.client;
    this.client = undefined;
    await client?.dispose({ exitGraceMs: stopped ? IDLE_HELPER_EXIT_GRACE_MS : TEARDOWN_HELPER_EXIT_GRACE_MS });
  }

  /**
   * The helper, with an answer about the adapter that is current. A helper
   * started just now answered in its handshake; a running one is asked again,
   * because `wintun.dll` may have been put in place since it started.
   */
  private async withCurrentCapabilities(): Promise<NativeHelperClient> {
    const running = this.client?.running ? this.client : undefined;
    const client = await this.connect();
    if (client !== running) {
      return client;
    }
    try {
      await client.refreshCapabilities();
      return client;
    } catch (error) {
      if (this.active || this.startAttempted) {
        // It holds a dataplane, which a restart would take down; the answer
        // it gave before is the best one to be had.
        return client;
      }
      // An idle helper that will not answer is replaced: it holds nothing.
      this.options.onDiagnostic?.("warning", `The native helper did not answer a capability check; restarting it: ${errorMessage(error)}`);
      if (this.client === client) {
        this.client = undefined;
      }
      await client.dispose();
      return this.connect();
    }
  }

  private connect(): Promise<NativeHelperClient> {
    if (this.client?.running) {
      return Promise.resolve(this.client);
    }
    this.connecting ??= this.spawnHelper().finally(() => {
      this.connecting = undefined;
    });
    return this.connecting;
  }

  private async spawnHelper(attached = false): Promise<NativeHelperClient> {
    const generation = ++this.helperGeneration;
    // A dataplane goes with the helper that ran it; nothing owes a stop to
    // the new one.
    this.startAttempted = false;
    const detached = process.platform === "win32" && !attached;
    const client = await NativeHelperClient.start(this.options.executablePath, {
      env: {
        [WINTUN_SEARCH_DIRECTORIES_ENV]: wintunSearchDirectories(this.options.userDataDirectory).join(";")
      },
      // The helper reports dataplane progress on stderr, which is the same
      // channel the rest of the app already surfaces as diagnostics.
      onStderrLine: (line) => this.handleStderrLine(generation, line),
      onEvent: (event) => this.handleHelperEvent(event),
      onClosed: (error) => this.handleHelperClosed(generation, error),
      // It owns the routing table: if Electron goes before it has finished
      // taking its routes down, it carries on rather than being killed.
      detached
    });
    if (this.disposed || generation !== this.helperGeneration) {
      await client.dispose();
      throw new Error("The dataplane controller is disposed.");
    }
    if (detached && client.handshake?.capabilities.routeRecovery !== true) {
      // A detached helper has no console, and one built before it started
      // netsh without one - which came with routeRecovery - makes Windows
      // open a visible console window for every route it changes. Only
      // `npm run dev` runs such a helper, until the committed binaries are
      // rebuilt; it is started again attached, as before.
      await client.dispose();
      return this.spawnHelper(true);
    }
    this.client = client;
    this.clientGeneration = generation;
    return client;
  }

  private handleStderrLine(generation: number, line: string): void {
    const classified = classifyHelperStderrLine(line);
    if (classified.fatalReason !== undefined) {
      this.fatalLine = { generation, reason: classified.fatalReason };
    }
    this.options.onDiagnostic?.(classified.level, classified.message);
  }

  /** The diagnostics a command produced arrive as events beside its response. */
  private handleHelperEvent(event: ServiceEvent): void {
    if (event.type === "diagnostics-appended") {
      this.options.onDiagnostic?.(event.entry.level, event.entry.message);
    }
  }

  /**
   * A helper that dies takes its adapter, and therefore the capture routes,
   * with it. Traffic returns to the physical interface rather than stopping,
   * so this is never a silent fallback: whoever relies on the adapter hears
   * of it, or the user does.
   *
   * What counts is whether the helper that died ran the active dataplane,
   * not whether it is the newest one: its exit can be reported only after a
   * replacement was started.
   */
  private handleHelperClosed(generation: number, error: Error): void {
    if (generation === this.helperGeneration) {
      this.startAttempted = false;
    }
    if (generation !== this.dataplaneGeneration || !this.active || this.disposed || this.stopping) {
      // Not carrying traffic, or being taken down on purpose: the stop that
      // is running reports its own outcome.
      return;
    }
    this.setActive(false);
    const reason = this.fatalLine?.generation === generation ? this.fatalLine.reason : describeHelperExit(error);
    if (this.unexpectedStopListeners.size === 0) {
      this.options.onDiagnostic?.("error", "TUN dataplane stopped unexpectedly: " + reason);
      return;
    }
    for (const listener of [...this.unexpectedStopListeners]) {
      try {
        listener(reason);
      } catch {
        // One listener failing must not keep the others from hearing it.
      }
    }
  }
}

export interface ClassifiedHelperLine {
  level: "info" | "warning" | "error";
  message: string;
  /** Set for the line a helper writes before exiting because its dataplane failed. */
  fatalReason?: string;
}

/**
 * Sorts one stderr line of the helper into a diagnostic level.
 *
 * The helper writes `dataplane <level>: <message>` for its own diagnostics,
 * routine progress included, `dataplane fatal: <reason>` once before it exits
 * because the adapter died, and a JSON object `{"level", "message"}` when it
 * cannot start at all. A line in none of those forms is something going
 * wrong outside them: a failure before the protocol is up (the DLL search
 * hardening, a bad argument), or the Go runtime's own output when the helper
 * crashes. Those are warnings, and the first line of a crash - `panic:` or
 * `fatal error:`, which name the cause of the exit that follows - is an
 * error, so a filter by level still finds why TUN went away.
 */
export function classifyHelperStderrLine(line: string): ClassifiedHelperLine {
  const message = line.trim();
  if (message.toLowerCase().startsWith(FATAL_STDERR_PREFIX)) {
    const reason = message.slice(FATAL_STDERR_PREFIX.length).trim();
    return { level: "error", message, fatalReason: reason || "the helper reported that its dataplane failed" };
  }
  const prefixed = /^dataplane (error|warning|warn|info):/iu.exec(message);
  if (prefixed) {
    const label = prefixed[1].toLowerCase();
    return { level: label === "error" ? "error" : label === "info" ? "info" : "warning", message };
  }
  if (message.startsWith("{")) {
    try {
      const parsed = JSON.parse(message) as { level?: unknown; message?: unknown };
      if (typeof parsed.message === "string" && parsed.message.trim()) {
        const level = parsed.level === "error" || parsed.level === "warning" || parsed.level === "info" ? parsed.level : "info";
        return { level, message: parsed.message.trim() };
      }
    } catch {
      // Not the helper's JSON; read it as plain text below.
    }
  }
  return { level: /^(panic|fatal error):/u.test(message) ? "error" : "warning", message };
}

function describeHelperExit(error: Error): string {
  if (error.message.includes(`(${DATAPLANE_FATAL_EXIT_CODE})`)) {
    return `${error.message} The helper reported that its dataplane failed.`;
  }
  return error.message;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
