import { NativeHelperClient } from "./native-helper-client.js";
import { WINTUN_SEARCH_DIRECTORIES_ENV, wintunSearchDirectories } from "./tun-routing.js";
import type { DataplaneStartRequest } from "./local-ipc-protocol.js";

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
}

/**
 * The surface the transports use, so a test can drive routing decisions
 * without an elevated helper.
 */
export interface DataplaneController {
  readonly isActive: boolean;
  probe(): Promise<DataplaneAvailability>;
  start(request: DataplaneStartRequest): Promise<void>;
  stop(): Promise<void>;
  dispose(): Promise<void>;
}

export interface DataplaneAvailability {
  available: boolean;
  /** Why the dataplane cannot be used, for a diagnostic the user can act on. */
  reason?: string;
}

export class NativeDataplaneController implements DataplaneController {
  private client: NativeHelperClient | undefined;
  private starting: Promise<void> | undefined;
  private active = false;
  private disposed = false;

  constructor(private readonly options: NativeDataplaneOptions) {}

  /** True while an adapter is up and carrying traffic. */
  get isActive(): boolean {
    return this.active;
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
      client = await this.connect();
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
  async start(request: DataplaneStartRequest): Promise<void> {
    if (this.disposed) {
      throw new Error("The dataplane controller is disposed.");
    }
    const started = (this.starting ?? Promise.resolve()).catch(() => undefined).then(async () => {
      const client = await this.connect();
      await client.startDataplane(request);
      this.active = true;
    });
    this.starting = started.catch(() => undefined);
    await started;
  }

  /** Takes the dataplane down and restores routing. Safe to call when idle. */
  async stop(): Promise<void> {
    const client = this.client;
    if (!client?.running || !this.active) {
      this.active = false;
      return;
    }
    try {
      await client.stopDataplane();
    } finally {
      this.active = false;
    }
  }

  /**
   * Stops the dataplane and releases the helper.
   *
   * The stop is attempted first and its failure is reported rather than
   * swallowed: killing the helper with capture routes still installed would
   * leave the machine unable to reach the network.
   */
  async dispose(): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    try {
      await this.stop();
    } catch (error) {
      this.options.onDiagnostic?.("error", "TUN dataplane did not stop cleanly: " + errorMessage(error));
    }
    const client = this.client;
    this.client = undefined;
    await client?.dispose();
  }

  private async connect(): Promise<NativeHelperClient> {
    if (this.client?.running) {
      return this.client;
    }
    this.client = await NativeHelperClient.start(this.options.executablePath, {
      env: {
        [WINTUN_SEARCH_DIRECTORIES_ENV]: wintunSearchDirectories(this.options.userDataDirectory).join(";")
      },
      // The helper reports dataplane progress on stderr, which is the same
      // channel the rest of the app already surfaces as diagnostics.
      onStderrLine: (line) => this.options.onDiagnostic?.("warning", line),
      onClosed: (error) => {
        // A helper that dies takes its adapter, and therefore the capture
        // routes, with it. Traffic returns to the physical interface rather
        // than stopping, so this is a warning the user must see and not a
        // silent fallback.
        if (this.active) {
          this.active = false;
          this.options.onDiagnostic?.("error", "TUN dataplane stopped unexpectedly: " + error.message);
        }
      }
    });
    return this.client;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
