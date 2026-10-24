import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  assessRendererIpcTrust,
  isRendererPermissionAllowed,
  isRendererPermissionCheckAllowed,
  RendererNavigationPolicy,
  isTrustedRendererUrl
} from "../src/main/app/renderer-security.js";
import { productionContentSecurityPolicy } from "../vite.config.js";

describe("renderer navigation security", () => {
  it("allows the selected renderer URL and harmless hash changes", () => {
    const trusted = "file:///opt/shadow%20ssh/renderer/index.html";
    expect(isTrustedRendererUrl(`${trusted}#settings`, trusted)).toBe(true);
    expect(new RendererNavigationPolicy([trusted]).permits(`${trusted}#logs`)).toBe(true);
  });

  it("rejects remote, sibling, query-modified, and malformed URLs", () => {
    const trusted = "http://127.0.0.1:5173/";
    const policy = new RendererNavigationPolicy([trusted]);
    expect(policy.permits("https://example.com/")).toBe(false);
    expect(policy.permits("http://127.0.0.1:5173/admin")).toBe(false);
    expect(policy.permits("http://127.0.0.1:5173/?redirect=https://example.com")).toBe(false);
    expect(policy.permits("not a url")).toBe(false);
  });

  it("can explicitly trust a main-process generated fallback page", () => {
    const policy = new RendererNavigationPolicy(["file:///app/index.html"]);
    const fallback = "data:text/html;charset=utf-8,%3Ch1%3EFailed%3C%2Fh1%3E";
    policy.allow(fallback);
    expect(policy.permits(fallback)).toBe(true);
  });

  it("accepts Windows file URL casing differences without trusting siblings or queries", () => {
    const trusted = "file:///C:/Program%20Files/Shadow%20SSH/resources/app.asar/dist/renderer/index.html";

    expect(
      isTrustedRendererUrl(
        "file:///c:/program%20files/shadow%20ssh/resources/app.asar/dist/renderer/INDEX.HTML#settings",
        trusted,
        "win32"
      )
    ).toBe(true);
    expect(isTrustedRendererUrl(`${trusted}?page=settings`, trusted, "win32")).toBe(false);
    expect(isTrustedRendererUrl(trusted.replace("index.html", "other.html"), trusted, "win32")).toBe(false);
    expect(new RendererNavigationPolicy([trusted], "win32").permits(trusted.toLowerCase())).toBe(true);
    expect(
      isTrustedRendererUrl(
        "file://localhost/c:/Program Files/Shadow SSH/resources/app.asar/dist/renderer/index.html",
        trusted,
        "win32"
      )
    ).toBe(true);
    expect(
      isTrustedRendererUrl(
        "file:///C%3A/Program%20Files/Shadow%20SSH/resources/app.asar/dist/renderer/index.html",
        trusted,
        "win32"
      )
    ).toBe(true);
    expect(isTrustedRendererUrl("file:///C:/Program%20Files/Shadow%20SSH/resources/app.asar/dist/renderer/a%2Fb", trusted, "win32")).toBe(false);
    expect(isTrustedRendererUrl("file://user@localhost/C:/Shadow%20SSH/index.html", trusted, "win32")).toBe(false);
  });

  it("rejects an app-owned BrowserWindow when the sender frame is unavailable", () => {
    expect(
      assessRendererIpcTrust({
        senderWebContentsId: 17,
        applicationWindowWebContentsIds: [17],
        senderUrl: "file:///C:/Shadow%20SSH/resources/app.asar/dist/renderer/index.html",
        trustedUrl: "file:///c:/shadow ssh/resources/app.asar/dist/renderer/index.html",
        senderFrame: null,
        mainFrame: { frameTreeNodeId: 12 },
        platform: "win32"
      })
    ).toEqual({ trusted: false, reason: "missing-frame" });
  });

  it("rejects unknown windows, child frames, detached frames, and navigated renderer URLs", () => {
    const trustedUrl = "file:///C:/Shadow%20SSH/resources/app.asar/dist/renderer/index.html";
    const base = {
      senderWebContentsId: 17,
      applicationWindowWebContentsIds: [17],
      senderUrl: trustedUrl,
      trustedUrl,
      mainFrame: { frameTreeNodeId: 12 },
      frameWebContentsId: 17,
      platform: "win32" as const
    };

    expect(assessRendererIpcTrust({ ...base, applicationWindowWebContentsIds: [18] })).toEqual({
      trusted: false,
      reason: "unknown-window"
    });
    expect(
      assessRendererIpcTrust({
        ...base,
        senderFrame: {
          frameTreeNodeId: 13,
          detached: false,
          parent: {}
        }
      })
    ).toEqual({ trusted: false, reason: "not-main-frame" });
    expect(
      assessRendererIpcTrust({
        ...base,
        senderFrame: {
          frameTreeNodeId: 12,
          detached: true,
          parent: null
        }
      })
    ).toEqual({ trusted: false, reason: "detached-frame" });
    expect(assessRendererIpcTrust({ ...base, senderUrl: "https://example.com/" })).toEqual({
      trusted: false,
      reason: "url-mismatch"
    });
  });

  it("accepts a live top frame across a RenderFrameHost swap", () => {
    const trustedUrl = "file:///C:/Shadow%20SSH/resources/app.asar/dist/renderer/index.html";
    expect(
      assessRendererIpcTrust({
        senderWebContentsId: 17,
        applicationWindowWebContentsIds: [17],
        senderUrl: trustedUrl,
        trustedUrl,
        senderFrame: {
          frameTreeNodeId: 12,
          detached: false,
          parent: null
        },
        mainFrame: { frameTreeNodeId: 12 },
        frameWebContentsId: 17,
        platform: "win32"
      })
    ).toEqual({ trusted: true });
  });

  it("rejects a frame that does not belong to the registered WebContents", () => {
    const trustedUrl = "file:///C:/Shadow%20SSH/resources/app.asar/dist/renderer/index.html";
    expect(
      assessRendererIpcTrust({
        senderWebContentsId: 17,
        applicationWindowWebContentsIds: [17],
        senderUrl: trustedUrl,
        trustedUrl,
        senderFrame: {
          frameTreeNodeId: 12,
          detached: false,
          parent: null
        },
        mainFrame: { frameTreeNodeId: 12 },
        frameWebContentsId: 18,
        platform: "win32"
      })
    ).toEqual({ trusted: false, reason: "frame-owner-mismatch" });
  });
});

describe("renderer web permissions", () => {
  const trustedUrl = "file:///opt/shadow/resources/app.asar/dist/renderer/index.html";
  const allowed = (permission: string, overrides: Partial<Parameters<typeof isRendererPermissionAllowed>[0]> = {}): boolean =>
    isRendererPermissionAllowed({ permission, fromApplicationWindow: true, requestingUrl: trustedUrl, trustedUrl, ...overrides });

  it("lets the app's own window save an exported rules file", () => {
    expect(allowed("fileSystem")).toBe(true);
    expect(allowed("fileSystem", { requestingUrl: `${trustedUrl}#routing` })).toBe(true);
  });

  it("denies everything the renderer does not use", () => {
    for (const permission of [
      "media",
      "geolocation",
      "notifications",
      "clipboard-read",
      "clipboard-sanitized-write",
      "display-capture",
      "fullscreen",
      "openExternal",
      "pointerLock",
      "keyboardLock",
      "midiSysex",
      "hid",
      "serial",
      "usb",
      "unknown"
    ]) {
      expect(allowed(permission), permission).toBe(false);
    }
  });

  it("lets Electron confirm the save picker's grant, which it checks with no window and only the origin", () => {
    // The exact shape Electron uses for a File System Access grant's status:
    // no WebContents, the origin as a URL, no requesting URL. Refusing it made
    // the write after the picker fail, with the chosen file already emptied.
    const check = (overrides: Partial<Parameters<typeof isRendererPermissionCheckAllowed>[0]> = {}): boolean =>
      isRendererPermissionCheckAllowed({
        permission: "fileSystem",
        hasWebContents: false,
        fromApplicationWindow: false,
        requestingOrigin: "file:///",
        requestingUrl: "",
        filePath: "/Users/me/Documents/shadow-rules.json",
        trustedUrl,
        ...overrides
      });
    expect(check()).toBe(true);
    // An unpackaged run serves the renderer from the dev server.
    expect(check({ requestingOrigin: "http://localhost:5173/", trustedUrl: "http://localhost:5173/" })).toBe(true);

    expect(check({ requestingOrigin: "https://example.com/" })).toBe(false);
    expect(check({ requestingOrigin: "http://localhost:5174/", trustedUrl: "http://localhost:5173/" })).toBe(false);
    expect(check({ filePath: undefined })).toBe(false);
    expect(check({ permission: "media" })).toBe(false);
    // With a WebContents the window is required, as for a request.
    expect(check({ hasWebContents: true, requestingUrl: trustedUrl })).toBe(false);
    expect(check({ hasWebContents: true, fromApplicationWindow: true, requestingUrl: trustedUrl })).toBe(true);
  });

  it("denies even file access to anything but the trusted window and page", () => {
    expect(allowed("fileSystem", { fromApplicationWindow: false })).toBe(false);
    expect(allowed("fileSystem", { requestingUrl: "https://example.com/" })).toBe(false);
    expect(allowed("fileSystem", { requestingUrl: "file:///opt/shadow/resources/app.asar/dist/renderer/other.html" })).toBe(false);
    expect(allowed("fileSystem", { requestingUrl: "" })).toBe(false);
  });
});

describe("renderer content security policy", () => {
  const source = readFileSync("index.html", "utf8");

  it("forbids base and form targets and plugins in every build", () => {
    expect(source).toContain("base-uri 'none'");
    expect(source).toContain("form-action 'none'");
    expect(source).toContain("object-src 'none'");
  });

  it("ships without the dev-server origins", () => {
    expect(source).toContain("ws://127.0.0.1:5173");
    const built = productionContentSecurityPolicy(source);
    expect(built).not.toContain("127.0.0.1:5173");
    expect(built).toContain("connect-src 'self';");
    expect(built).toContain("script-src 'self';");
    expect(built).toContain("base-uri 'none'");
  });

  it("fails the build rather than ship a policy it could not clean", () => {
    expect(() => productionContentSecurityPolicy("<html><head></head></html>")).toThrow(/Content-Security-Policy/u);
    expect(() =>
      productionContentSecurityPolicy(
        '<meta http-equiv="Content-Security-Policy" content="connect-src \'self\' http://127.0.0.1:5173/hmr" />'
      )
    ).toThrow(/dev server/u);
  });
});
