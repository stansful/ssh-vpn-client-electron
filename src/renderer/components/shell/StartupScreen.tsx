import { FolderOpen, RotateCcw } from "lucide-react";
import { version as appVersion } from "../../../../package.json";
import { api } from "../../api.js";
import type { StartupState } from "../../hooks/useSnapshot.js";
import { useToasts } from "../../hooks/useToasts.js";
import { Button } from "../ui/Button.js";
import { StatusDot } from "../ui/Badge.js";
import { Progress } from "../ui/Display.js";

function detectPlatformLabel(): string | undefined {
  const source = `${navigator.userAgent} ${navigator.platform}`;
  if (/Windows|Win32|Win64/iu.test(source)) {
    return "Windows";
  }
  if (/Mac/iu.test(source)) {
    return "macOS";
  }
  if (/Linux|X11/iu.test(source)) {
    return "Linux";
  }
  return undefined;
}

function isTimeout(error: string): boolean {
  return /did not arrive within/iu.test(error);
}

/**
 * Shown before the sidebar exists: a splash while the snapshot loads (also
 * after "Free memory while hidden" released the window), and "couldn't load"
 * with Try again and Open log folder when it fails. Follows the system theme
 * until the saved theme loads.
 */
export function StartupScreen({ startup, onRetry }: { startup: StartupState; onRetry: () => void }): JSX.Element {
  const { toast } = useToasts();
  const platform = detectPlatformLabel();
  const foot = (
    <p className="splash-foot">
      <span className="mono">{platform ? `${appVersion} · ${platform}` : appVersion}</span>
    </p>
  );

  if (startup.phase !== "error") {
    return (
      <main className="sys-screen" aria-busy="true">
        <div className="splash">
          <div className="splash-mark" aria-hidden="true">
            <span className="splash-glow" />
            <span className="splash-ring" />
            <span className="splash-ring r2" />
            <img src="./icon.svg" alt="" />
          </div>
          <p className="splash-name">Shadow SSH</p>
          <p className="splash-status" aria-live="polite">
            <span className="splash-shimmer">Starting secure services…</span>
          </p>
          <Progress label="Starting Shadow SSH" className="splash-bar" />
          {foot}
        </div>
      </main>
    );
  }

  const tries = startup.attempts <= 1 ? "No answer after 1 try" : `No answer after ${startup.attempts} tries`;
  return (
    <main className="sys-screen">
      <div className="splash">
        <div className="splash-mark" aria-hidden="true">
          <img src="./icon.svg" alt="" />
          <StatusDot tone="danger" />
        </div>
        <div className="stack-sm" role="alert" style={{ alignItems: "center", textAlign: "center" }}>
          <h1 className="splash-title">Shadow SSH couldn’t load its state</h1>
          <p className="splash-text">
            {isTimeout(startup.error)
              ? "The background service didn’t send your settings within 10 seconds. It may still be starting."
              : "The background service answered with an error, so your servers and settings can’t be shown yet. It may still be starting."}
          </p>
        </div>
        <div className="raw">
          <span>{startup.error}</span>
        </div>
        <div className="row-wrap splash-actions">
          <Button variant="primary" icon={RotateCcw} autoFocus onClick={onRetry}>
            Try again
          </Button>
          <Button
            icon={FolderOpen}
            onClick={() => {
              void api
                .openLogFolder()
                .then((opened) => {
                  if (!opened) {
                    toast({ id: "open-logs", tone: "error", title: "Couldn't open the log folder", message: "Look for main.log in the Shadow SSH data folder." });
                  }
                })
                .catch(() => {
                  toast({ id: "open-logs", tone: "error", title: "Couldn't open the log folder", message: "Look for main.log in the Shadow SSH data folder." });
                });
            }}
          >
            Open log folder
          </Button>
        </div>
        <p className="splash-foot" aria-live="polite">
          {tries}. Try again shows the splash and asks the background service again.
        </p>
      </div>
    </main>
  );
}
