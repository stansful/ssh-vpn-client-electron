import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Top-level renderer navigations are deliberately restricted to URLs that the
 * main process selected. Hash changes are harmless and are ignored, while a
 * different path, query, origin, or protocol is treated as a different page.
 */
export class RendererNavigationPolicy {
  private readonly trustedUrls = new Set<string>();

  constructor(
    initialUrls: string[] = [],
    private readonly platform: NodeJS.Platform = process.platform
  ) {
    for (const url of initialUrls) {
      this.allow(url);
    }
  }

  allow(url: string): void {
    const normalized = normalizeRendererUrl(url, this.platform);
    if (!normalized) {
      throw new Error("Cannot trust an invalid renderer URL.");
    }
    this.trustedUrls.add(normalized);
  }

  permits(url: string): boolean {
    const normalized = normalizeRendererUrl(url, this.platform);
    return normalized !== undefined && this.trustedUrls.has(normalized);
  }
}

export interface RendererRequestFrame {
  detached: boolean;
  frameTreeNodeId: number;
  parent: unknown | null;
}

export interface RendererMainFrameIdentity {
  frameTreeNodeId: number;
}

export type RendererIpcTrustDecision =
  | { trusted: true }
  | {
      trusted: false;
      reason:
        | "detached-frame"
        | "frame-owner-mismatch"
        | "missing-frame"
        | "not-main-frame"
        | "unknown-window"
        | "url-mismatch";
    };

export function isTrustedRendererUrl(
  candidateUrl: string,
  trustedUrl: string,
  platform: NodeJS.Platform = process.platform
): boolean {
  const trusted = normalizeRendererUrl(trustedUrl, platform);
  return trusted !== undefined && normalizeRendererUrl(candidateUrl, platform) === trusted;
}

/**
 * Trust only a registered app WebContents, its live top-level frame and the
 * selected renderer URL. RenderFrameHost process/routing IDs can change during
 * navigation, while frameTreeNodeId remains stable for the logical frame.
 */
export function assessRendererIpcTrust({
  senderWebContentsId,
  applicationWindowWebContentsIds,
  senderUrl,
  trustedUrl,
  senderFrame,
  mainFrame,
  frameWebContentsId,
  platform = process.platform
}: {
  senderWebContentsId: number;
  applicationWindowWebContentsIds: readonly number[];
  senderUrl: string;
  trustedUrl: string;
  senderFrame?: RendererRequestFrame | null;
  mainFrame?: RendererMainFrameIdentity | null;
  frameWebContentsId?: number;
  platform?: NodeJS.Platform;
}): RendererIpcTrustDecision {
  if (!applicationWindowWebContentsIds.includes(senderWebContentsId)) {
    return { trusted: false, reason: "unknown-window" };
  }
  if (!isTrustedRendererUrl(senderUrl, trustedUrl, platform)) {
    return { trusted: false, reason: "url-mismatch" };
  }
  if (!senderFrame || !mainFrame) {
    return { trusted: false, reason: "missing-frame" };
  }
  if (senderFrame.detached) {
    return { trusted: false, reason: "detached-frame" };
  }
  if (frameWebContentsId !== senderWebContentsId) {
    return { trusted: false, reason: "frame-owner-mismatch" };
  }
  if (senderFrame.parent !== null || senderFrame.frameTreeNodeId !== mainFrame.frameTreeNodeId) {
    return { trusted: false, reason: "not-main-frame" };
  }
  return { trusted: true };
}

/**
 * Web permissions the app's own renderer may use. Clipboard, notifications
 * and external links all go through main-process IPC, so the only one left is
 * `fileSystem`: "Export rules" writes the file the user just picked in the
 * save dialog.
 */
const RENDERER_PERMISSIONS: ReadonlySet<string> = new Set(["fileSystem"]);

/**
 * Electron grants every permission request when no handler is set. This
 * denies all of them except the ones the trusted renderer needs, and only
 * for that renderer.
 */
export function isRendererPermissionAllowed(input: {
  permission: string;
  /** The requesting WebContents is one of the app's registered windows. */
  fromApplicationWindow: boolean;
  /** URL of the requesting frame (or its WebContents). */
  requestingUrl: string;
  trustedUrl: string;
  platform?: NodeJS.Platform;
}): boolean {
  return (
    RENDERER_PERMISSIONS.has(input.permission) &&
    input.fromApplicationWindow &&
    isTrustedRendererUrl(input.requestingUrl, input.trustedUrl, input.platform)
  );
}

/**
 * Electron's permission *check*, which is asked more than a request is. For
 * every File System Access grant - the write grant the save picker just gave
 * included - Electron checks the grant's status with no WebContents and only
 * the origin that holds it, and once a check handler is set its answer
 * replaces the grant's. Insisting on the window there refused "Export rules"
 * its own write, after the picker had already created or emptied the chosen
 * file. So a `fileSystem` check without a WebContents is allowed for a file
 * path held by the trusted renderer's origin; the grant itself only ever came
 * from that renderer's picker, through the request handler. Every other check
 * needs the window, as a request does.
 */
export function isRendererPermissionCheckAllowed(input: {
  permission: string;
  /** Whether the check names a WebContents at all. */
  hasWebContents: boolean;
  /** The requesting WebContents is one of the app's registered windows. */
  fromApplicationWindow: boolean;
  /** The origin Electron passes to the check, e.g. "file:///". */
  requestingOrigin: string;
  /** URL of the requesting frame (or its WebContents). */
  requestingUrl: string;
  /** The path of a `fileSystem` check. */
  filePath?: string;
  trustedUrl: string;
  platform?: NodeJS.Platform;
}): boolean {
  if (input.hasWebContents) {
    return isRendererPermissionAllowed(input);
  }
  if (input.permission !== "fileSystem" || !input.filePath) {
    return false;
  }
  const trustedOrigin = rendererOrigin(input.trustedUrl);
  return trustedOrigin !== undefined && rendererOrigin(input.requestingOrigin) === trustedOrigin;
}

/** The origin a renderer URL is served from, as Electron reports it: every file: URL shares one. */
function rendererOrigin(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (url.protocol === "file:") {
      return "file://";
    }
    return url.origin === "null" ? undefined : url.origin;
  } catch {
    return undefined;
  }
}

function normalizeRendererUrl(value: string, platform: NodeJS.Platform): string | undefined {
  try {
    const url = new URL(value);
    url.hash = "";
    if (platform === "win32" && url.protocol === "file:") {
      if (url.username || url.password || url.port) {
        return undefined;
      }
      // Canonicalize both Node's pathToFileURL output and Chromium's packaged
      // file URL. This absorbs drive/UNC casing, localhost, escaped spaces and
      // separator differences without weakening path or query matching.
      const canonicalPath = path.win32.normalize(fileURLToPath(url, { windows: true })).toLowerCase();
      return `win32-file:${canonicalPath}${url.search}`;
    }
    return url.href;
  } catch {
    return undefined;
  }
}
