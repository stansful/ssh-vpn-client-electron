import { TriangleAlert } from "lucide-react";
import { useId, useState } from "react";
import { isStartupFailure } from "../../lib/runtime-message.js";
import { useAppData } from "../../hooks/useAppData.js";
import type { AppSnapshot } from "../../../shared/types.js";
import { Button, DisclosureButton } from "../ui/Button.js";
import { Callout } from "../ui/Callout.js";
import { CopyButton } from "../ui/CopyButton.js";
import { Collapse } from "../ui/Display.js";

const SHOWN_LINES = 4;

/** Remembered for the renderer's lifetime: the banner stays until restart, even after diagnostics are cleared. */
let rememberedFailure: string | undefined;

/**
 * Text of the "Startup failed: …" error when the connection core did not
 * start and Connect fell back to a simulator; undefined otherwise.
 */
export function startupFailureText(snapshot: AppSnapshot): string | undefined {
  if (snapshot.startupFailure?.trim()) {
    return snapshot.startupFailure.trim();
  }
  const { runtime } = snapshot;
  if (isStartupFailure(runtime.message)) {
    return runtime.message.trim();
  }
  for (let index = snapshot.diagnostics.length - 1; index >= 0; index -= 1) {
    const entry = snapshot.diagnostics[index];
    if (isStartupFailure(entry.message)) {
      return entry.message.trim();
    }
  }
  return undefined;
}

function useStartupFailure(snapshot: AppSnapshot): string | undefined {
  const found = startupFailureText(snapshot);
  if (found) {
    rememberedFailure = found;
  }
  return rememberedFailure;
}

/**
 * Pinned above every page while the connection core failed to start: Connect
 * only simulates a session. Can't be dismissed; details show the first lines
 * of the error with Copy and a way to Activity.
 */
export function PreviewBanner(): JSX.Element | null {
  const { snapshot, store, navigate } = useAppData();
  const failure = useStartupFailure(snapshot);
  const [open, setOpen] = useState(false);
  const detailsId = useId();
  if (!failure) {
    return null;
  }
  const lines = failure.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  const shown = lines.slice(0, SHOWN_LINES);
  const note =
    lines.length > SHOWN_LINES
      ? `First ${SHOWN_LINES} of ${lines.length} lines.${store.settings.loggingEnabled ? " The full text is in Activity." : " Copy takes the full text."}`
      : store.settings.loggingEnabled
        ? "The same text is in Activity."
        : "";

  return (
    <div className="preview-banner rise">
      <Callout
        tone="warn"
        icon={TriangleAlert}
        role="status"
        title="Preview only · device traffic is not redirected"
        actions={
          <DisclosureButton variant="secondary" open={open} controls={detailsId} onClick={() => setOpen((current) => !current)}>
            {open ? "Hide details" : "Show details"}
          </DisclosureButton>
        }
      >
        The connection service didn’t start, so Connect only simulates a session. No tunnel is created and your apps stay on the direct network. Quit and reopen Shadow SSH to try again.
      </Callout>
      <Collapse open={open} id={detailsId}>
        <div className="stack-sm preview-banner-details">
          <div className="term term-lines" role="log" aria-label="Startup error details">
            {shown.map((line, index) => (
              <span key={index} className={index === 0 ? "term-line t-err" : "term-line t-dim"}>
                {line}
              </span>
            ))}
          </div>
          <div className="row-wrap" style={{ justifyContent: "space-between" }}>
            <span className="hint">{note}</span>
            <div className="row" style={{ gap: 4 }}>
              <CopyButton text={failure} label="Copy startup error" withText />
              {store.settings.loggingEnabled ? (
                <Button variant="ghost" size="sm" onClick={() => navigate("activity")}>
                  Open activity
                </Button>
              ) : null}
            </div>
          </div>
        </div>
      </Collapse>
    </div>
  );
}
