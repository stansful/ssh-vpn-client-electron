import {
  Clock,
  Info,
  Network,
  Pencil,
  RotateCcw,
  ShieldAlert,
  Sunrise,
  Terminal,
  TriangleAlert,
  X,
  Zap,
  type LucideIcon
} from "lucide-react";
import { useCallback, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import type { AppSnapshot, GlobalTab } from "../../../../shared/types.js";
import {
  hysteria2CheckState,
  phaseOf,
  presentConnection,
  redirectsSystemTraffic,
  transportLabel,
  type ConnectionPresentation
} from "../../../lib/connection.js";
import { diagnosticSource } from "../../../lib/diagnostics.js";
import { formatClock, platformLabel, plural, protocolLabel } from "../../../lib/format.js";
import {
  formatLocalProxy,
  isGenericStateMessage,
  isStartupFailure,
  runtimeLocalProxy,
  type ReconnectReason
} from "../../../lib/runtime-message.js";
import { Badge, Button, Callout, Icon, LinkButton, Orb } from "../../ui/index.js";
import { HYSTERIA2_INSECURE_PROFILE_WARNING } from "../profiles/link-preview.js";
import { closedForRoutingHint, describeSshFailure, networkChangeSummary, splitLead } from "./connect-copy.js";
import { resolveTarget, sessionTargetName, summarizeRouting, type ConnectTarget, type TargetState } from "./connect-target.js";
import { HeroFacts } from "./HeroFacts.js";
import { TargetPicker } from "./TargetPicker.js";

export interface ConnectHeroProps {
  /** The transport tab being viewed (not necessarily the one running). */
  view: GlobalTab;
  /** Switches the Connect tab ("Show Xray"). */
  onShowTransport: (transport: GlobalTab) => void;
}

const REASON_ICON: Record<ReconnectReason["kind"], LucideIcon> = {
  "network-change": Network,
  wake: Sunrise,
  "clock-jump": Clock,
  watchdog: RotateCcw,
  "session-lost": Info,
  stuck: TriangleAlert
};

const OTHER_VERB: Partial<Record<AppSnapshot["runtime"]["state"], string>> = {
  Connecting: "connecting",
  Connected: "connected",
  Reconnecting: "reconnecting",
  Disconnecting: "disconnecting"
};

/** Hero copy and orb behaviour on top of the shared presentation, for cases only Connect knows about. */
function adjustPresentation(base: ConnectionPresentation, view: GlobalTab, targets: TargetState): ConnectionPresentation {
  const ssh = view === "ssh";
  if (base.phase === "disconnecting") {
    return { ...base, lockHint: "Available again in a moment." };
  }
  if (base.phase === "off" && targets.noneSelected && !targets.target) {
    const noun = ssh ? "server" : "profile";
    return {
      ...base,
      orbState: "blocked",
      orbDisabled: true,
      primaryAction: "none",
      orbLabel: `Choose a ${noun} first`,
      orbAriaLabel: `Connect (choose a ${noun} first)`,
      description: `Your traffic goes direct. Choose one of your ${plural(targets.count, noun)} below, then tap the button.`
    };
  }
  if (base.phase === "error" && targets.noneSelected && !targets.target) {
    return { ...base, orbDisabled: true };
  }
  return base;
}

/** When the newest error from this transport was logged, for "Reason from Xray · 12:06:12". */
function lastErrorTime(snapshot: AppSnapshot, transport: GlobalTab): string | undefined {
  for (let index = snapshot.diagnostics.length - 1; index >= 0; index -= 1) {
    const entry = snapshot.diagnostics[index];
    if (entry.level === "error" && diagnosticSource(entry) === transport) {
      return formatClock(entry.at);
    }
  }
  return undefined;
}

/**
 * The Connect hero: state word, orb (the one primary action), picker and the
 * callouts that explain the state. Describes the viewed transport; the other
 * transport running shows as a callout, never as this tab's state.
 */
export function ConnectHero({ view, onShowTransport }: ConnectHeroProps): JSX.Element {
  const { snapshot, store, runtime, activeTransport, environment, run, toast, navigate } = useAppData();
  const ssh = view === "ssh";
  const label = transportLabel(view);
  const [pending, setPending] = useState(false);
  const hintId = useId();

  const targets = useMemo(() => resolveTarget(snapshot, view), [snapshot, view]);
  const target: ConnectTarget | undefined = targets.target;
  const routing = useMemo(() => summarizeRouting(store), [store]);
  const otherName = activeTransport !== view ? sessionTargetName(snapshot) : undefined;
  const redirects = redirectsSystemTraffic(environment.platform);

  const presentation = adjustPresentation(
    presentConnection({
      transport: view,
      activeTransport,
      runtime,
      platform: environment.platform,
      routingMode: store.routingMode,
      targetName: target?.name,
      targetAddress: target?.address,
      protocolLabel: target?.profile ? protocolLabel(target.profile.protocol) : undefined,
      otherTargetName: otherName,
      routingBlocked: routing.blocked,
      noTarget: targets.noneSaved,
      unsupportedTarget: Boolean(target?.unsupported),
      // Xray says Connected for Hysteria 2 before the server answers over UDP; the tunnel check is the proof.
      hysteria2Check: hysteria2CheckState({
        runtime,
        activeTransport,
        protocol: ssh ? undefined : target?.profile?.protocol,
        lastTunnelCheck: snapshot.lastTunnelCheck
      })
    }),
    view,
    targets
  );
  const { phase } = presentation;

  // SSH failures get a plain sentence; the service's words stay underneath for support.
  let description = presentation.description;
  let technical: string | undefined;
  if (phase === "error" && !isStartupFailure(runtime.message) && !isGenericStateMessage(runtime.message)) {
    if (ssh) {
      const copy = describeSshFailure(runtime.message, {
        name: runtime.activeConfigName ?? target?.name ?? "The server",
        username: target?.config?.username
      });
      description = copy.description;
      technical = copy.technical;
    } else {
      technical = runtime.message.trim();
    }
  }
  const xrayReasonTime = !ssh && technical ? lastErrorTime(snapshot, "xray") : undefined;
  const closedHint = phase === "off" && routing.blocked ? closedForRoutingHint(snapshot.attention) : undefined;

  let pickerHint: string | undefined;
  if (presentation.pickerLocked) {
    pickerHint = presentation.lockHint;
  } else if (targets.noneSaved) {
    pickerHint = ssh ? "Have a VLESS, VMess, Trojan or Hysteria 2 link instead? Switch to Xray at the top." : "Have an SSH server instead? Switch to SSH at the top.";
  } else if (phase === "off" && presentation.primaryAction === "connect") {
    pickerHint = routing.hint;
  }

  const proxyOnlyPlatform = environment.platform === "macos" || environment.platform === "linux";
  const eyebrow = `${label} tunnel${phase === "connected" && proxyOnlyPlatform ? ` · ${platformLabel(environment.platform)}` : ""}`;
  const swapKey = `${view}-${presentation.heroState}`;

  // Keep keyboard focus in the hero when the focused control disappears with a state change.
  const heroRef = useRef<HTMLElement>(null);
  const orbRef = useRef<HTMLButtonElement>(null);
  const lastFocused = useRef<HTMLElement>();
  useLayoutEffect(() => {
    const previous = lastFocused.current;
    if (previous && !previous.isConnected && (document.activeElement === document.body || document.activeElement === null)) {
      const next = orbRef.current && !orbRef.current.disabled ? orbRef.current : heroRef.current;
      next?.focus({ preventScroll: true });
      lastFocused.current = next ?? undefined;
    }
  });

  const connect = useCallback(async (): Promise<void> => {
    const other = presentation.otherTransportActive ? { label: transportLabel(activeTransport), name: otherName } : undefined;
    setPending(true);
    const result = await run(() => (ssh ? api.connect() : api.connectProxy()), {
      errorTitle: ssh ? "Couldn't connect" : "Couldn't start Xray"
    });
    setPending(false);
    if (!result || result.activeTransport !== view) {
      return;
    }
    if (other) {
      toast({
        tone: "info",
        title: `Switched to ${transportLabel(view)}`,
        message: `The ${other.label} tunnel${other.name ? ` to ${other.name}` : ""} was closed first.`
      });
    }
    if (phaseOf(result.runtime) === "connected") {
      const proxy = runtimeLocalProxy(result.runtime);
      const name = result.runtime.activeConfigName ?? target?.name;
      toast({
        tone: "success",
        title: "Connected",
        message: [name, proxy ? `local proxy ${formatLocalProxy(proxy)}` : undefined].filter(Boolean).join(" · ") || undefined
      });
    }
  }, [activeTransport, otherName, presentation.otherTransportActive, run, ssh, target?.name, toast, view]);

  const disconnect = useCallback(async (): Promise<void> => {
    setPending(true);
    const result = await run(() => api.disconnect(), { errorTitle: "Couldn't disconnect" });
    setPending(false);
    if (result?.runtime.state === "Disconnected") {
      toast({
        tone: "info",
        title: "Disconnected",
        message: redirects ? "Direct network settings restored." : "The tunnel and its local proxy are closed."
      });
    }
  }, [redirects, run, toast]);

  const dismissError = useCallback(async (): Promise<void> => {
    setPending(true);
    await run(() => api.dismissConnectionError(), { errorTitle: "Couldn't dismiss the error" });
    setPending(false);
  }, [run]);

  const primary = (): void => {
    switch (presentation.primaryAction) {
      case "connect":
      case "retry":
      case "switch":
        void connect();
        break;
      case "disconnect":
      case "stop-reconnecting":
        void disconnect();
        break;
      default:
        break;
    }
  };

  const editTarget = (): void => {
    if (ssh) {
      navigate("servers", target?.id ? { type: "edit-server", id: target.id } : undefined);
    } else {
      navigate("profiles");
    }
  };

  const reason = phase === "reconnecting" ? presentation.reconnectReason : undefined;
  const otherState = runtime.state;
  const otherLabel = transportLabel(activeTransport);
  const otherVerb = phaseOf(runtime) === "preview" ? "running a preview" : OTHER_VERB[otherState] ?? "on";

  return (
    <section
      ref={heroRef}
      className="hero rise"
      data-state={presentation.heroState}
      aria-live="polite"
      aria-label="Connection"
      tabIndex={-1}
      style={{ "--d": 1 } as CSSProperties}
      onFocus={(event) => {
        lastFocused.current = event.target as HTMLElement;
      }}
      onBlur={(event) => {
        const next = event.relatedTarget as Node | null;
        if (next && !event.currentTarget.contains(next)) {
          lastFocused.current = undefined;
        }
      }}
    >
      <div className="hero-top">
        <span className="eyebrow">{eyebrow}</span>
        <Badge tone={presentation.badge.tone} dot={!presentation.badge.spinner} spinner={presentation.badge.spinner}>
          {presentation.badge.text}
        </Badge>
      </div>

      <div className="hero-body">
        <Orb
          ref={orbRef}
          state={presentation.orbState}
          ariaLabel={presentation.orbAriaLabel}
          label={presentation.orbLabel}
          disabled={presentation.orbDisabled || pending}
          icon={phase === "preview" ? ShieldAlert : undefined}
          onClick={primary}
        />

        <div className="hero-copy">
          <div className="cn-copy anim-swap" key={swapKey}>
            <h2 className="state-word">{presentation.stateWord}</h2>
            <p className="state-desc">{description}</p>
            {ssh && technical ? <code className="cn-code">{technical}</code> : null}
            {!ssh && technical ? (
              <div className="cn-reason">
                <span className="cn-reason-label">
                  <Icon icon={TriangleAlert} size="sm" />
                  Reason from Xray{xrayReasonTime ? ` · ${xrayReasonTime}` : ""}
                </span>
                <span className="cn-reason-text">{technical}</span>
                {store.settings.loggingEnabled ? <LinkButton onClick={() => navigate("activity")}>See the full log</LinkButton> : null}
              </div>
            ) : null}
            {closedHint ? (
              <span className="cn-hintline">
                <Icon icon={Clock} size="sm" />
                <span>{closedHint}</span>
              </span>
            ) : null}
          </div>

          <div className="stack-sm cn-pick">
            <span className="eyebrow">{ssh ? "Server" : "Profile"}</span>
            <TargetPicker transport={view} state={targets} locked={presentation.pickerLocked} describedBy={pickerHint ? hintId : undefined} />
            {pickerHint ? (
              <span className="hint" id={hintId}>
                {pickerHint}
              </span>
            ) : null}
          </div>

          {phase === "error" ? (
            <div className="hero-actions cn-actions anim-swap">
              <Button variant="primary" icon={RotateCcw} disabled={presentation.orbDisabled || pending} onClick={() => void connect()}>
                Try again
              </Button>
              <Button icon={ssh ? Pencil : Zap} onClick={editTarget}>
                {ssh ? "Edit server" : "Choose another profile"}
              </Button>
              <Button variant="ghost" disabled={pending} onClick={() => void dismissError()}>
                Dismiss
              </Button>
            </div>
          ) : null}

          {phase === "reconnecting" ? (
            <div className="hero-actions cn-actions anim-swap">
              <Button variant="danger" icon={X} disabled={pending} onClick={() => void disconnect()}>
                Stop reconnecting
              </Button>
            </div>
          ) : null}
        </div>
      </div>

      {reason ? <ReconnectCallout reason={reason} ssh={ssh} canEdit={Boolean(!ssh || target?.id)} onEdit={editTarget} /> : null}

      {presentation.otherTransportActive ? (
        <Callout
          tone={otherState === "Connected" && phaseOf(runtime) === "connected" ? "ok" : "info"}
          icon={activeTransport === "xray" ? Zap : Terminal}
          title={`${otherLabel} is ${otherVerb}${otherName ? ` · ${otherName}` : ""}`}
          actions={
            <Button size="sm" onClick={() => onShowTransport(activeTransport)}>
              Show {otherLabel}
            </Button>
          }
        >
          Connecting here closes the {otherLabel} tunnel first, then opens {label}.
        </Callout>
      ) : null}

      {routing.blocked && !presentation.session ? (
        <Callout
          tone="warn"
          icon={TriangleAlert}
          title="Nothing to route yet"
          actions={
            <Button size="sm" onClick={() => navigate("routing")}>
              Open routing
            </Button>
          }
        >
          Split tunnel sends only what you pick. Turn on a rule or a domain list, then connect.
        </Callout>
      ) : null}

      {target?.unsupported && !presentation.session ? (
        <Callout
          tone="warn"
          icon={TriangleAlert}
          title={target.unsupported === "security" ? "Unknown security mode" : "Unknown transport"}
          actions={
            <Button size="sm" onClick={() => navigate("profiles")}>
              Choose another profile
            </Button>
          }
        >
          {target.unsupported === "security"
            ? "This link asks for a security setting the bundled Xray engine can’t run. Supported modes are none, tls and reality."
            : "This link uses a transport the bundled Xray engine doesn’t recognise. Pick a profile with a known transport, such as tcp, ws or grpc."}
        </Callout>
      ) : null}

      {/* A warning, not a block: the profile connects, unless its server's certificate is self-signed. */}
      {target?.insecureWithoutPin && !target.unsupported && !presentation.session ? (
        <Callout tone="warn" icon={ShieldAlert} title="Certificate checks stay on">
          {HYSTERIA2_INSECURE_PROFILE_WARNING}
        </Callout>
      ) : null}

      {phase === "connected" ? <HeroFacts transport={view} target={target} /> : null}
    </section>
  );
}

function ReconnectCallout({
  reason,
  ssh,
  canEdit,
  onEdit
}: {
  reason: ReconnectReason;
  ssh: boolean;
  canEdit: boolean;
  onEdit: () => void;
}): JSX.Element {
  if (reason.likelyStuck) {
    const { lead, rest } = splitLead(reason.detail);
    return (
      <Callout
        tone="warn"
        icon={TriangleAlert}
        title={reason.title}
        actions={
          canEdit ? (
            <Button size="sm" onClick={onEdit}>
              {ssh ? "Edit server" : "Choose another profile"}
            </Button>
          ) : undefined
        }
      >
        {reason.technical ? (
          <>
            {lead}: <code className="cn-inline">{reason.technical}</code>. {rest}
          </>
        ) : (
          reason.detail
        )}
      </Callout>
    );
  }
  const change = reason.kind === "network-change" ? networkChangeSummary(reason.technical) : undefined;
  return (
    <Callout tone="info" icon={REASON_ICON[reason.kind]} title={reason.title}>
      {change ? `${change}. ${reason.detail}` : reason.detail}
    </Callout>
  );
}
