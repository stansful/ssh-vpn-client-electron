import { Check, RotateCcw, ShieldAlert, TriangleAlert } from "lucide-react";
import { useEffect, useRef } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import { useNavigation } from "../../../hooks/useNavigation.js";
import { platformLabel } from "../../../lib/format.js";
import { formatLocalProxy, runtimeLocalProxy } from "../../../lib/runtime-message.js";
import type { PageProps } from "../../../types.js";
import { PageHeader } from "../../shell/index.js";
import { Badge, Button, Callout, Mono } from "../../ui/index.js";
import { DomainListsCard } from "./DomainListsCard.js";
import { ModeCard } from "./ModeCard.js";
import { RoutingDialogs } from "./RoutingDialogs.js";
import { RulesCard } from "./RulesCard.js";
import type { SaveStatus } from "./useRoutingAutosave.js";
import { useRoutingController, type RoutingController } from "./useRoutingController.js";

const SAVE_BADGE: Record<SaveStatus, { tone: "ok" | "busy" | "danger" | "warn"; text: string }> = {
  saved: { tone: "ok", text: "Saved" },
  saving: { tone: "busy", text: "Saving…" },
  failed: { tone: "danger", text: "Not saved" },
  unapplied: { tone: "warn", text: "Saved · not applied" }
};

/** Routing: the traffic mode, community domain lists and your own rules. Every change saves on its own. */
export function RoutingPage({ intent }: PageProps): JSX.Element {
  const ctl = useRoutingController();
  const { clearIntent } = useNavigation();
  const rulesCard = useRef<HTMLElement>(null);
  const { setTab } = ctl;

  useEffect(() => {
    if (intent?.type !== "routing-tab") {
      return undefined;
    }
    setTab(intent.tab);
    clearIntent();
    // Land on the rules card (the page itself just scrolled to the top).
    const frame = window.requestAnimationFrame(() => {
      const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
      rulesCard.current?.scrollIntoView({ block: "start", behavior: reduce ? "auto" : "smooth" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [clearIntent, intent, setTab]);

  return (
    <>
      <PageHeader
        eyebrow="Tunnel"
        title="Routing"
        sub="Decide what goes through the tunnel. Changes apply instantly, even while connected."
        actions={<SaveBadge ctl={ctl} />}
      />
      <PageCallouts ctl={ctl} />
      <ModeCard ctl={ctl} />
      <DomainListsCard ctl={ctl} />
      <RulesCard ctl={ctl} ref={rulesCard} />
      <RoutingDialogs ctl={ctl} />
    </>
  );
}

function SaveBadge({ ctl }: { ctl: RoutingController }): JSX.Element {
  const { status } = ctl.autosave.state;
  const badge = SAVE_BADGE[status];
  const retry = status === "failed" || status === "unapplied";
  return (
    <div className="rt-save" role="status" aria-live={status === "failed" ? "assertive" : "polite"} title="Changes save automatically">
      <Badge
        key={status}
        tone={badge.tone}
        spinner={status === "saving"}
        icon={status === "saved" ? Check : retry ? TriangleAlert : undefined}
        className="anim-swap"
      >
        {badge.text}
      </Badge>
      {retry ? (
        <Button size="sm" icon={RotateCcw} onClick={ctl.autosave.retry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

function PageCallouts({ ctl }: { ctl: RoutingController }): JSX.Element {
  const { runtime, store, navigate } = useAppData();
  const { status, reason } = ctl.autosave.state;
  // The main process writes a failed save to Activity, but only while events are recorded.
  const inActivity = store.settings.loggingEnabled && store.settings.diagnosticsLoggingEnabled;
  const proxy = runtimeLocalProxy(runtime);
  const platform = platformLabel(ctl.platform);
  return (
    <>
      {!ctl.steers ? (
        <Callout tone="info" className="rise" title={`On ${platform}, rules don’t redirect system traffic`}>
          {proxy ? (
            <>
              Apps use the tunnel only when they point to the local proxy <Mono>{formatLocalProxy(proxy)}</Mono>.
            </>
          ) : (
            "Apps use the tunnel only when they point to the local proxy, which Connect shows once you’re connected."
          )}{" "}
          Here the mode only decides whether Connect is allowed.
        </Callout>
      ) : null}

      {status === "failed" ? (
        <Callout
          tone="danger"
          role="alert"
          className="rise"
          title="Your last change isn’t saved"
          actions={
            <>
              <Button size="sm" onClick={ctl.autosave.retry}>
                Try again
              </Button>
              {inActivity ? (
                <Button size="sm" variant="ghost" onClick={() => navigate("activity")}>
                  Open activity
                </Button>
              ) : null}
            </>
          }
        >
          It stays on screen for now, but Shadow drops it the next time the window reloads.
          {inActivity ? " The reason is in Activity." : reason ? ` ${reason}` : ""}
        </Callout>
      ) : null}

      {status === "unapplied" ? (
        <Callout
          tone="warn"
          icon={TriangleAlert}
          className="rise"
          title={`Saved, but not applied to ${ctl.sessionName ?? "the running tunnel"}`}
          actions={
            <Button size="sm" onClick={ctl.autosave.retry}>
              Try again
            </Button>
          }
        >
          {reason ? `${reason} ` : ""}The running tunnel still uses your previous rules. Try again, or reconnect to apply them.
        </Callout>
      ) : null}

      {ctl.blocked ? (
        <Callout
          tone="warn"
          icon={ShieldAlert}
          className="rise"
          title="Connect is blocked by routing"
          actions={
            <Button size="sm" disabled={Boolean(ctl.listBusy.proxy)} onClick={ctl.enableProxyList}>
              Turn on Blocked in Russia
            </Button>
          }
        >
          Split tunnel has nothing to route. Turn on a rule or Blocked in Russia, then connect again. Russian services doesn’t count: it only keeps
          sites direct.
        </Callout>
      ) : null}
    </>
  );
}
