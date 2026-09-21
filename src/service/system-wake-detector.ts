import os from "node:os";

export type SystemWakeReason = "clock-jump" | "network-changed";

export interface SystemWakeEvent {
  reason: SystemWakeReason;
  detail: string;
}

export interface SystemWakeDetectorOptions {
  /** How often the detector looks; 5 s keeps a resume visible within seconds. */
  tickIntervalMs?: number;
  /**
   * A tick arriving later than this past its due time means the process was
   * not running: the machine slept, or the OS froze the process. Timers that
   * were armed before the gap have then fired late or not at all, and the
   * socket underneath the session has most likely been abandoned by every NAT
   * on the path.
   */
  clockJumpThresholdMs?: number;
  /** Interface names that never mean the machine changed networks. */
  ignoredInterfaceNames?: readonly string[];
  now?: () => number;
  interfaces?: () => NodeJS.Dict<os.NetworkInterfaceInfo[]>;
  setTimer?: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  clearTimer?: (timer: NodeJS.Timeout) => void;
}

export const DEFAULT_WAKE_TICK_INTERVAL_MS = 5_000;
export const DEFAULT_CLOCK_JUMP_THRESHOLD_MS = 15_000;

/**
 * Interfaces the tunnel itself, other VPNs and virtualisation create. They come
 * and go with those products, not with the machine's connectivity, and the
 * app's own adapter appears the moment routing is applied - a "change" that
 * would otherwise probe every fresh session.
 */
const DEFAULT_IGNORED_INTERFACE_PATTERN =
  /^(lo\d*|utun\d*|tun\d*|tap\d*|wg\d*|ppp\d*|ipsec\d*|zt[a-z0-9]*|tailscale\d*|docker\d*|veth[\w-]*|br-[\w-]*|virbr\d*|vmnet\d*|vboxnet\d*|bridge\d*|awdl\d*|llw\d*|anpi\d*|ap\d*|gif\d*|stf\d*|XHC\d*)$/i;
/**
 * Windows names adapters after the product that created them, so a prefix
 * match on the friendly name is the only workable rule there: Hyper-V and WSL
 * switches ("vEthernet (WSL)"), VMware/VirtualBox host adapters, Teredo/ISATAP
 * transition tunnels, Bluetooth PAN and the loopback pseudo-interface all
 * appear and disappear without the machine changing networks.
 */
const DEFAULT_IGNORED_INTERFACE_PREFIX_PATTERN =
  /^(vEthernet|Hyper-V|VMware|VirtualBox|Teredo|isatap|6to4|Bluetooth|Loopback|Local Area Connection\* |Npcap|Npf|TAP-|OpenVPN|WireGuard|ZeroTier|Tailscale|NordLynx|ProtonVPN|Mullvad|Radmin|Hamachi)/i;

/**
 * Notices the two things an Electron main process is not told about directly
 * but which almost always mean the SSH socket is gone: the process stopped
 * running for a while (sleep, hibernation, a frozen process), and the machine's
 * addresses changed (Wi-Fi roaming, docking, a hotspot, a VPN on the side).
 *
 * `powerMonitor` reports the common sleep case, and the owner should still
 * wire it; this detector is the backstop for the platforms and situations
 * where no such event arrives. It costs one timer and one `getifaddrs` call
 * per tick.
 */
export class SystemWakeDetector {
  private readonly tickIntervalMs: number;
  private readonly clockJumpThresholdMs: number;
  private readonly ignoredInterfaceNames: ReadonlySet<string>;
  private readonly now: () => number;
  private readonly interfaces: () => NodeJS.Dict<os.NetworkInterfaceInfo[]>;
  private readonly setTimer: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly clearTimer: (timer: NodeJS.Timeout) => void;
  private timer: NodeJS.Timeout | undefined;
  private expectedTickAt = 0;
  private networkSignature = "";

  constructor(
    private readonly onWake: (event: SystemWakeEvent) => void,
    options: SystemWakeDetectorOptions = {}
  ) {
    this.tickIntervalMs = options.tickIntervalMs ?? DEFAULT_WAKE_TICK_INTERVAL_MS;
    this.clockJumpThresholdMs = options.clockJumpThresholdMs ?? DEFAULT_CLOCK_JUMP_THRESHOLD_MS;
    this.ignoredInterfaceNames = new Set((options.ignoredInterfaceNames ?? []).map((name) => name.toLowerCase()));
    this.now = options.now ?? Date.now;
    this.interfaces = options.interfaces ?? os.networkInterfaces;
    this.setTimer = options.setTimer ?? ((callback, delayMs) => setTimeout(callback, delayMs));
    this.clearTimer = options.clearTimer ?? ((timer) => clearTimeout(timer));
  }

  get running(): boolean {
    return this.timer !== undefined;
  }

  start(): void {
    if (this.timer) {
      return;
    }
    this.networkSignature = this.readNetworkSignature();
    this.armTimer();
  }

  stop(): void {
    if (!this.timer) {
      return;
    }
    this.clearTimer(this.timer);
    this.timer = undefined;
  }

  /** Runs one observation now; exposed so tests and owners can force a check. */
  tick(): void {
    if (!this.timer) {
      return;
    }
    // A forced tick must not leave the armed timer running beside the new one.
    this.clearTimer(this.timer);
    this.timer = undefined;
    const now = this.now();
    const lateByMs = now - this.expectedTickAt;
    this.armTimer();

    if (lateByMs >= this.clockJumpThresholdMs) {
      // Read the interfaces first: after a sleep they usually changed too, and
      // one wake for the pair is enough.
      this.networkSignature = this.readNetworkSignature();
      this.onWake({
        reason: "clock-jump",
        detail: `the process did not run for about ${Math.round(lateByMs / 1000)} s`
      });
      return;
    }

    const signature = this.readNetworkSignature();
    if (signature !== this.networkSignature) {
      const previous = this.networkSignature;
      this.networkSignature = signature;
      this.onWake({ reason: "network-changed", detail: describeSignatureChange(previous, signature) });
    }
  }

  private armTimer(): void {
    this.expectedTickAt = this.now() + this.tickIntervalMs;
    this.timer = this.setTimer(() => this.tick(), this.tickIntervalMs);
    this.timer.unref?.();
  }

  private readNetworkSignature(): string {
    let entries: NodeJS.Dict<os.NetworkInterfaceInfo[]>;
    try {
      entries = this.interfaces();
    } catch {
      // A failed enumeration says nothing about the network; keep the last view.
      return this.networkSignature;
    }
    const parts: string[] = [];
    for (const [name, addresses] of Object.entries(entries)) {
      if (!addresses || this.isIgnoredInterface(name)) {
        continue;
      }
      for (const address of addresses) {
        if (address.internal || isLinkLocal(address)) {
          continue;
        }
        parts.push(`${name}=${address.address}`);
      }
    }
    parts.sort();
    return parts.join(";");
  }

  private isIgnoredInterface(name: string): boolean {
    return (
      this.ignoredInterfaceNames.has(name.toLowerCase()) ||
      DEFAULT_IGNORED_INTERFACE_PATTERN.test(name) ||
      DEFAULT_IGNORED_INTERFACE_PREFIX_PATTERN.test(name)
    );
  }
}

function isLinkLocal(address: os.NetworkInterfaceInfo): boolean {
  // Older Node releases reported the family as a number.
  const family = String(address.family);
  if (family === "IPv6" || family === "6") {
    return /^fe[89ab][0-9a-f]:/i.test(address.address);
  }
  return address.address.startsWith("169.254.");
}

function describeSignatureChange(previous: string, current: string): string {
  const before = new Set(previous.split(";").filter(Boolean));
  const after = new Set(current.split(";").filter(Boolean));
  const gone = [...before].filter((entry) => !after.has(entry));
  const added = [...after].filter((entry) => !before.has(entry));
  const summary: string[] = [];
  if (gone.length > 0) {
    summary.push(`lost ${gone.slice(0, 4).join(", ")}${gone.length > 4 ? ` and ${gone.length - 4} more` : ""}`);
  }
  if (added.length > 0) {
    summary.push(`gained ${added.slice(0, 4).join(", ")}${added.length > 4 ? ` and ${added.length - 4} more` : ""}`);
  }
  return summary.length > 0 ? `network interfaces changed (${summary.join("; ")})` : "network interfaces changed";
}
