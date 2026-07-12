import { describe, expect, it } from "vitest";
import {
  createEnergyAwareWindowOptions,
  shouldDeliverRendererEvent,
  shouldLogRendererConsoleMessage,
  SystemEnergyPolicy
} from "../src/main/app/energy-policy.js";

describe("main-process energy policy", () => {
  it("does not paint a window created hidden in the tray", () => {
    const hidden = createEnergyAwareWindowOptions(true);
    expect(hidden.show).toBe(false);
    expect(hidden.paintWhenInitiallyHidden).toBe(false);
    expect(hidden.webPreferences).toMatchObject({
      backgroundThrottling: true,
      spellcheck: false,
      autoplayPolicy: "document-user-activation-required",
      webgl: false
    });

    const visible = createEnergyAwareWindowOptions(false);
    expect(visible.show).toBe(true);
    expect(visible.paintWhenInitiallyHidden).toBe(true);
  });

  it("slows only low-priority process discovery on battery and thermal pressure", () => {
    const policy = new SystemEnergyPolicy({ onBatteryPower: false });
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(30_000);
    expect(policy.processRoutingRefreshIntervalMs(false)).toBe(60_000);

    policy.setOnBatteryPower(true);
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(120_000);
    expect(policy.processRoutingRefreshIntervalMs(false)).toBe(120_000);

    policy.setThermalState("serious");
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(120_000);

    policy.setOnBatteryPower(false);
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(120_000);

    policy.setThermalState("nominal");
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(30_000);

    policy.setCpuSpeedLimitPercent(80);
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(120_000);
    policy.setCpuSpeedLimitPercent(100);
    expect(policy.processRoutingRefreshIntervalMs(true)).toBe(30_000);
  });

  it("suppresses production console noise while preserving warnings and development logs", () => {
    expect(shouldLogRendererConsoleMessage(true, 0)).toBe(false);
    expect(shouldLogRendererConsoleMessage(true, 1)).toBe(false);
    expect(shouldLogRendererConsoleMessage(true, 2)).toBe(true);
    expect(shouldLogRendererConsoleMessage(false, 0)).toBe(true);
  });

  it("delivers events only to a live foreground renderer", () => {
    const foreground = {
      windowDestroyed: false,
      webContentsDestroyed: false,
      visible: true,
      minimized: false
    };
    expect(shouldDeliverRendererEvent(foreground)).toBe(true);
    expect(shouldDeliverRendererEvent({ ...foreground, visible: false })).toBe(false);
    expect(shouldDeliverRendererEvent({ ...foreground, minimized: true })).toBe(false);
    expect(shouldDeliverRendererEvent({ ...foreground, windowDestroyed: true })).toBe(false);
    expect(shouldDeliverRendererEvent({ ...foreground, webContentsDestroyed: true })).toBe(false);
  });
});
