import { describe, expect, it, vi } from "vitest";

vi.mock("electron", () => ({
  BrowserWindow: class {},
  nativeTheme: { shouldUseDarkColors: true }
}));

const {
  crashPageAction,
  createCrashPageDataUrl,
  createCrashPageHtml,
  fitWindowSize,
  RENDERER_CRASH_RELOAD_WINDOW_MS,
  RendererCrashPolicy
} = await import("../src/main/app/main-window.js");

describe("renderer crash recovery", () => {
  it("reloads once, then shows the crash page for a second crash within a minute", () => {
    const policy = new RendererCrashPolicy();
    expect(policy.next(1_000)).toBe("reload");
    expect(policy.next(1_000 + RENDERER_CRASH_RELOAD_WINDOW_MS - 1)).toBe("crash-page");
    expect(policy.next(1_000 + RENDERER_CRASH_RELOAD_WINDOW_MS + 5)).toBe("reload");
  });

  it("never navigates again when the crash page itself goes down", () => {
    const policy = new RendererCrashPolicy();
    expect(policy.next(1_000, { reason: "crashed" })).toBe("reload");
    expect(policy.next(2_000, { reason: "crashed" })).toBe("crash-page");
    expect(policy.next(3_000, { reason: "crashed", crashPageShown: true })).toBe("stay");
    expect(policy.next(1_000 + RENDERER_CRASH_RELOAD_WINDOW_MS + 5, { reason: "crashed", crashPageShown: true })).toBe("stay");
  });

  it("does not relaunch a renderer that cannot start", () => {
    const policy = new RendererCrashPolicy();
    expect(policy.next(1_000, { reason: "launch-failed" })).toBe("stay");
    expect(policy.next(1_000 + RENDERER_CRASH_RELOAD_WINDOW_MS + 5, { reason: "integrity-failure" })).toBe("stay");
    // A later ordinary crash still gets its automatic reload.
    expect(policy.next(1_000 + 2 * RENDERER_CRASH_RELOAD_WINDOW_MS, { reason: "oom" })).toBe("reload");
  });

  it("recognises only the crash page's own links", () => {
    expect(crashPageAction("shadow-ssh://reload")).toBe("reload");
    expect(crashPageAction("shadow-ssh://reload/")).toBe("reload");
    expect(crashPageAction("shadow-ssh://open-logs")).toBe("open-logs");
    expect(crashPageAction("shadow-ssh://reload/../etc")).toBeUndefined();
    expect(crashPageAction("shadow-ssh://reload?x=1")).toBeUndefined();
    expect(crashPageAction("https://reload")).toBeUndefined();
    expect(crashPageAction("not a url")).toBeUndefined();
  });

  it("renders the board copy with the tunnel line and no script", () => {
    const html = createCrashPageHtml({
      tunnel: { tone: "on", text: "Tunnel still on · SSH · Frankfurt-01" },
      detail: "Renderer process gone: reason=crashed, exitCode=-1073741819"
    });
    expect(html).toContain("The interface stopped responding");
    expect(html).toContain("The window crashed, but your tunnel didn’t.");
    expect(html).toContain("Tunnel still on · SSH · Frankfurt-01");
    expect(html).toContain('href="shadow-ssh://reload"');
    expect(html).toContain('href="shadow-ssh://open-logs"');
    expect(html).toContain("Reload interface");
    expect(html).toContain("Open log folder");
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script/iu);
  });

  it("escapes names and drops the tunnel promise when it is off", () => {
    const html = createCrashPageHtml({
      tunnel: { tone: "off", text: "<img src=x onerror=alert(1)>" },
      detail: "reason=\"crashed\""
    });
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("reason=&quot;crashed&quot;");
    expect(html).toContain("The window crashed. Reload to get the controls back.");
    expect(createCrashPageDataUrl({ tunnel: { tone: "off", text: "Tunnel is off" }, detail: "x" })).toMatch(
      /^data:text\/html;charset=utf-8,/u
    );
  });
});

describe("window size", () => {
  const preferred = { width: 1200, height: 800 };
  const minimum = { width: 460, height: 600 };

  it("uses the preferred size when the screen has room", () => {
    expect(fitWindowSize(preferred, minimum, { width: 1920, height: 1040 })).toEqual(preferred);
    expect(fitWindowSize(preferred, minimum)).toEqual(preferred);
  });

  it("shrinks to the work area but never below the minimum", () => {
    expect(fitWindowSize(preferred, minimum, { width: 1366, height: 728 })).toEqual({ width: 1200, height: 728 });
    expect(fitWindowSize(preferred, minimum, { width: 400, height: 500 })).toEqual(minimum);
  });
});
