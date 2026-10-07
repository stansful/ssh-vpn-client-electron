import {
  ArrowRight,
  CircleAlert,
  DatabaseZap,
  Globe,
  Network,
  PlugZap,
  Route,
  ShieldAlert,
  ShieldCheck,
  SkipForward,
  Unplug,
  X,
  type LucideIcon
} from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import type { AttentionEvent, AttentionKind } from "../../../../shared/types.js";
import { formatClock } from "../../../lib/format.js";
import type { NavigateFn } from "../../../hooks/useNavigation.js";
import { Badge, Button, Card, Collapse, DisclosureButton, Icon, IconButton, IconTile, LevelPill, LinkButton } from "../../ui/index.js";
import { attentionAction, attentionTone, attentionWhen } from "./activity-attention.js";
import { sourceLabel } from "./activity-feed.js";

/** Collapse time of `.collapse` (--t-slow) before the dismissal is sent. */
const LEAVE_MS = 420;

const KIND_ICONS: Record<AttentionKind, LucideIcon> = {
  "split-tunnel-no-targets": Route,
  "tun-unavailable": Network,
  "reconnect-stopped": Unplug,
  "auto-connect-failed": PlugZap,
  "auto-connect-skipped": SkipForward,
  "system-proxy-restore-failed": Globe,
  "system-proxy-recovered": ShieldCheck,
  "storage-unreadable": DatabaseZap,
  other: CircleAlert
};

export interface AttentionCardProps {
  events: AttentionEvent[];
  /** Start of the running session, for "This connection" / "Previous connection". */
  sessionStart?: string;
  /** Dismisses one event, or all when `id` is omitted; resolves false when it failed. */
  onDismiss: (id?: string) => Promise<boolean>;
  navigate: NavigateFn;
}

/**
 * "Needs your attention": events that changed how traffic flows. They outlive
 * the live feed (cleared on each connect) until dismissed. Dismissed items
 * fold away first, then the dismissal is sent.
 */
export function AttentionCard({ events, sessionStart, onDismiss, navigate }: AttentionCardProps): JSX.Element {
  const [leaving, setLeaving] = useState<ReadonlySet<string>>(() => new Set());
  const initialIds = useRef(new Set(events.map((event) => event.id)));

  // Forget leaving ids once the snapshot no longer has them.
  useEffect(() => {
    setLeaving((current) => {
      const present = new Set(events.map((event) => event.id));
      const next = new Set([...current].filter((id) => present.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [events]);

  // The timer is deliberately not cancelled on unmount: a dismissal made just
  // before leaving the page must still reach the main process.
  const leave = (ids: string[], id?: string): void => {
    setLeaving((current) => new Set([...current, ...ids]));
    window.setTimeout(() => {
      void onDismiss(id).then((ok) => {
        if (!ok) {
          setLeaving((current) => new Set([...current].filter((candidate) => !ids.includes(candidate))));
        }
      });
    }, LEAVE_MS);
  };

  const remaining = events.filter((event) => !leaving.has(event.id));
  const tone = remaining.some((event) => event.level === "error") || remaining.length === 0 ? "danger" : "warn";

  return (
    <Collapse open={remaining.length > 0} className="ac-attn-wrap">
      <Card rise={1} className="ac-attn" data-tone={tone} aria-labelledby="ac-attn-title" aria-live="polite">
        <div className="card-head">
          <div className="card-title-wrap">
            <IconTile icon={ShieldAlert} tone={tone} className="ac-attn-tile" />
            <div className="card-title-copy">
              <h2 className="card-title" id="ac-attn-title">
                Needs your attention
                <Badge tone={tone} className="ac-attn-count">
                  {remaining.length}
                </Badge>
              </h2>
              <p className="card-sub">Events that changed how your traffic flows. They stay here across connects until you dismiss them.</p>
            </div>
          </div>
          <div className="card-tools">
            <Button variant="ghost" size="sm" disabled={remaining.length === 0} onClick={() => leave(events.map((event) => event.id))}>
              Dismiss all
            </Button>
          </div>
        </div>
        <div className="ac-attn-list">
          {events.map((event) => (
            <AttentionItem
              key={event.id}
              event={event}
              when={attentionWhen(event.at, sessionStart)}
              animateIn={!initialIds.current.has(event.id)}
              leaving={leaving.has(event.id)}
              onDismiss={() => leave([event.id], event.id)}
              navigate={navigate}
            />
          ))}
        </div>
      </Card>
    </Collapse>
  );
}

interface AttentionItemProps {
  event: AttentionEvent;
  when: string;
  /** Arrived while the page was open: unfold instead of appearing at once. */
  animateIn: boolean;
  leaving: boolean;
  onDismiss: () => void;
  navigate: NavigateFn;
}

function AttentionItem({ event, when, animateIn, leaving, onDismiss, navigate }: AttentionItemProps): JSX.Element {
  const [entered, setEntered] = useState(!animateIn);
  const [stepsOpen, setStepsOpen] = useState(false);
  const titleId = useId();
  const stepsId = useId();
  const tone = attentionTone(event.level);
  const action = attentionAction(event);

  useEffect(() => {
    if (entered) {
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => setEntered(true));
    return () => window.cancelAnimationFrame(frame);
  }, [entered]);

  return (
    <Collapse open={entered && !leaving}>
      <div className="ac-attn-pad">
        <article className="ac-attn-item" data-tone={tone} aria-labelledby={titleId}>
          <span className="ac-attn-ic" aria-hidden="true">
            <Icon icon={KIND_ICONS[event.kind] ?? CircleAlert} />
          </span>
          <div className="ac-attn-main">
            <div className="ac-attn-meta">
              <LevelPill level={event.level} />
              <span className="ac-time">{formatClock(event.at)}</span>
              <span className="ac-src">{sourceLabel(event.source)}</span>
              {when ? <span className="faint">{when}</span> : null}
            </div>
            <h3 className="ac-attn-title" id={titleId}>
              {event.title}
            </h3>
            <p className="ac-attn-desc">{event.message}</p>
            {action?.type === "tun-steps" ? (
              <Collapse open={stepsOpen} id={stepsId}>
                <ol className="ac-steps">
                  <li>Quit Shadow SSH from the tray icon. Closing the window only hides it.</li>
                  <li>
                    Right-click Shadow SSH and choose <strong>Run as administrator</strong>. Being signed in as an administrator is not the same thing.
                  </li>
                  <li>
                    Keep <span className="mono">wintun.dll</span> beside the app’s .exe, or in the app data folder next to the logs.
                  </li>
                  <li>
                    Connect again. When it works, the events below say “TUN routing is active”. The TUN switch itself is in{" "}
                    <LinkButton icon={null} onClick={() => navigate("routing", { type: "routing-tab", tab: "apps" })}>
                      Routing → Apps
                    </LinkButton>
                    .
                  </li>
                </ol>
              </Collapse>
            ) : null}
          </div>
          <div className="ac-attn-actions">
            {action?.type === "navigate" ? (
              <Button size="sm" iconAfter={ArrowRight} onClick={() => navigate(action.view, action.intent)}>
                {action.label}
              </Button>
            ) : null}
            {action?.type === "tun-steps" ? (
              <DisclosureButton variant="secondary" open={stepsOpen} controls={stepsId} onClick={() => setStepsOpen((open) => !open)}>
                {stepsOpen ? "Hide steps" : "How to enable"}
              </DisclosureButton>
            ) : null}
            <IconButton icon={X} label={`Dismiss: ${event.title}`} tooltip="Dismiss" onClick={onDismiss} />
          </div>
        </article>
      </div>
    </Collapse>
  );
}
