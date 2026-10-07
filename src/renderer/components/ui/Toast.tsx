import { ChevronDown, CircleX, Info, ShieldAlert, ShieldCheck, X, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState, type CSSProperties } from "react";
import type { ToastApi, ToastTone, VisibleToast } from "../../hooks/useToasts.js";
import { Button, IconButton } from "./Button.js";
import { IconTile } from "./Card.js";
import type { Tone } from "./Badge.js";
import { CopyButton } from "./CopyButton.js";
import { Collapse } from "./Display.js";
import { cx } from "./Icon.js";

const TONE: Record<ToastTone, { cls: string; tile: Tone; icon: LucideIcon }> = {
  success: { cls: "t-ok", tile: "ok", icon: ShieldCheck },
  info: { cls: "t-info", tile: "info", icon: Info },
  warning: { cls: "t-warn", tile: "warn", icon: ShieldAlert },
  error: { cls: "t-danger", tile: "danger", icon: CircleX }
};

/**
 * Bottom-right toast stack (newest at the bottom, up to three). Success and
 * info close themselves; the timer pauses while the toast is hovered or
 * focused. Errors keep raw text under Technical details with Copy.
 */
export function ToastViewport({ toasts, onDismiss }: { toasts: VisibleToast[]; onDismiss: ToastApi["dismiss"] }): JSX.Element {
  return (
    <div className="toast-dock" aria-live="polite" aria-relevant="additions text">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onDismiss }: { toast: VisibleToast; onDismiss: ToastApi["dismiss"] }): JSX.Element {
  const [paused, setPaused] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const remaining = useRef(toast.duration ?? 0);
  const startedAt = useRef(Date.now());
  const tone = TONE[toast.tone];
  const timed = toast.duration !== null && toast.duration > 0;

  // A replacement (same id) restarts the timer.
  useEffect(() => {
    remaining.current = toast.duration ?? 0;
    startedAt.current = Date.now();
  }, [toast.revision, toast.duration]);

  useEffect(() => {
    if (!timed || paused || toast.leaving) {
      return undefined;
    }
    startedAt.current = Date.now();
    const timer = window.setTimeout(() => onDismiss(toast.id), Math.max(0, remaining.current));
    return () => {
      window.clearTimeout(timer);
      remaining.current -= Date.now() - startedAt.current;
    };
  }, [onDismiss, paused, timed, toast.id, toast.leaving, toast.revision]);

  const runAction = (): void => {
    const action = toast.action;
    if (!action) {
      return;
    }
    setActionBusy(true);
    void Promise.resolve()
      .then(action.onClick)
      .finally(() => {
        setActionBusy(false);
        if (action.dismiss !== false) {
          onDismiss(toast.id);
        }
      });
  };

  const actionButton = toast.action ? (
    <Button size="sm" icon={toast.action.icon} busy={actionBusy} onClick={runAction}>
      {toast.action.label}
    </Button>
  ) : null;
  const sideAction = toast.action?.placement === "side";

  return (
    <div
      className={cx("toast", tone.cls)}
      role={toast.tone === "error" ? "alert" : "status"}
      data-leaving={toast.leaving ? "true" : undefined}
      data-paused={paused ? "true" : undefined}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
          setPaused(false);
        }
      }}
    >
      <IconTile icon={toast.icon ?? tone.icon} tone={tone.tile} className="toast-icon" />
      <div className="toast-body anim-swap" key={toast.revision}>
        <span className="toast-title">{toast.title}</span>
        {toast.message ? <span className="toast-text">{toast.message}</span> : null}
        {(actionButton && !sideAction) || toast.details ? (
          <div className="toast-acts">
            {sideAction ? null : actionButton}
            {toast.details ? (
              <Button
                variant="ghost"
                size="sm"
                iconAfter={ChevronDown}
                aria-expanded={detailsOpen}
                data-open={detailsOpen ? "true" : "false"}
                onClick={() => setDetailsOpen((current) => !current)}
              >
                Technical details
              </Button>
            ) : null}
          </div>
        ) : null}
        {toast.details ? (
          <Collapse open={detailsOpen} className="toast-details">
            <div className="raw">
              <span>{toast.details}</span>
              <CopyButton text={toast.details} label="Copy technical details" />
            </div>
          </Collapse>
        ) : null}
      </div>
      {sideAction ? <div className="toast-actions">{actionButton}</div> : null}
      <IconButton icon={X} label="Dismiss notification" tooltip="Dismiss" onClick={() => onDismiss(toast.id)} />
      {timed ? <span className="toast-timer" key={`timer-${toast.revision}`} style={{ animationDuration: `${toast.duration}ms` } as CSSProperties} /> : null}
    </div>
  );
}
