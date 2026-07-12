import type { BrowserWindowConstructorOptions } from "electron";

export type ThermalState = "unknown" | "nominal" | "fair" | "serious" | "critical";

const AC_PROCESS_ROUTING_REFRESH_MS = 30_000;
const BACKGROUND_PROCESS_ROUTING_REFRESH_MS = 60_000;
const POWER_CONSTRAINED_PROCESS_ROUTING_REFRESH_MS = 120_000;

/**
 * Mutable, event-driven power state shared with low-priority background work.
 * Active tunnel I/O never consults this policy, so throughput is unaffected.
 */
export class SystemEnergyPolicy {
  private batteryPower: boolean;
  private thermalState: ThermalState;
  private cpuSpeedLimitPercent = 100;

  constructor({ onBatteryPower, thermalState = "unknown" }: { onBatteryPower: boolean; thermalState?: ThermalState }) {
    this.batteryPower = onBatteryPower;
    this.thermalState = thermalState;
  }

  processRoutingRefreshIntervalMs(hasForegroundWindow: boolean): number {
    if (
      this.batteryPower ||
      this.cpuSpeedLimitPercent < 100 ||
      this.thermalState === "serious" ||
      this.thermalState === "critical"
    ) {
      return POWER_CONSTRAINED_PROCESS_ROUTING_REFRESH_MS;
    }
    return hasForegroundWindow ? AC_PROCESS_ROUTING_REFRESH_MS : BACKGROUND_PROCESS_ROUTING_REFRESH_MS;
  }

  setOnBatteryPower(value: boolean): void {
    this.batteryPower = value;
  }

  setThermalState(value: ThermalState): void {
    this.thermalState = value;
  }

  setCpuSpeedLimitPercent(value: number): void {
    this.cpuSpeedLimitPercent = Number.isFinite(value) ? value : 100;
  }
}

export function createEnergyAwareWindowOptions(startHidden: boolean): Pick<
  BrowserWindowConstructorOptions,
  "show" | "paintWhenInitiallyHidden" | "webPreferences"
> {
  return {
    show: !startHidden,
    // Electron otherwise paints a show:false renderer and reports it as
    // document.visibilityState="visible", wasting CPU/GPU while in the tray.
    paintWhenInitiallyHidden: !startHidden,
    webPreferences: {
      backgroundThrottling: true,
      // Configuration fields contain technical identifiers, not prose. Avoid
      // loading dictionaries and running spellcheck on every edit.
      spellcheck: false,
      // The application has no media playback; do not let accidental content
      // create an autonomous audio/video workload.
      autoplayPolicy: "document-user-activation-required",
      // The renderer uses regular DOM/CSS/SVG and does not need a WebGL context.
      webgl: false
    }
  };
}

export function shouldLogRendererConsoleMessage(packaged: boolean, level: number): boolean {
  // Production debug/info console traffic is not actionable and can otherwise
  // keep waking the disk logger. Warnings and errors remain available.
  return !packaged || level >= 2;
}

export function shouldDeliverRendererEvent(state: {
  windowDestroyed: boolean;
  webContentsDestroyed: boolean;
  visible: boolean;
  minimized: boolean;
}): boolean {
  return !state.windowDestroyed && !state.webContentsDestroyed && state.visible && !state.minimized;
}
