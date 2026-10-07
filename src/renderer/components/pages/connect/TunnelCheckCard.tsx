import { Info, Pencil, Radar, RefreshCw } from "lucide-react";
import { Fragment, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { phaseOf } from "../../../lib/connection.js";
import { Badge, Button, Callout, Card, CardHeader, IconButton, LinkButton, Progress, type Tone } from "../../ui/index.js";
import { resolveTarget, sessionTargetName } from "./connect-target.js";
import { EndpointDialog } from "./EndpointDialog.js";
import { DEFAULT_CHECK_ENDPOINT, presentTunnelCheck, type TextSegment, type TunnelCheckKind } from "./tunnel-check.js";

const BADGE_TONE: Record<TunnelCheckKind, Tone> = {
  waiting: "neutral",
  idle: "neutral",
  checking: "busy",
  passed: "ok",
  note: "ok",
  failed: "danger"
};

function Segments({ segments }: { segments: TextSegment[] }): JSX.Element {
  return (
    <>
      {segments.map((segment, index) =>
        segment.kind === "mono" ? (
          <span key={index} className="mono">
            {segment.text}
          </span>
        ) : segment.kind === "code" ? (
          <code key={index} className="cn-inline">
            {segment.text}
          </code>
        ) : (
          <Fragment key={index}>{segment.text}</Fragment>
        )
      )}
    </>
  );
}

/**
 * The one tunnel check for the whole app, shared by SSH and Xray. It names
 * the tunnel it checked and clears when that tunnel stops.
 */
export function TunnelCheckCard(): JSX.Element {
  const { snapshot, store, runtime, activeTransport, run } = useAppData();
  const [requested, setRequested] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const endpoint = store.settings.checkEndpoint || DEFAULT_CHECK_ENDPOINT;
  const activePhase = phaseOf(runtime);
  const connected = activePhase === "connected" || activePhase === "preview";
  // Checks started from the tray or right after a connect show here too.
  const checking = requested || (snapshot.tunnelCheckRunning && connected);

  const activeProfile = activeTransport === "xray" ? resolveTarget(snapshot, "xray").target?.profile : undefined;
  const view = presentTunnelCheck({
    result: snapshot.lastTunnelCheck,
    endpoint,
    activeTransport,
    connected,
    checking,
    activeName: sessionTargetName(snapshot),
    activeProtocol: activeProfile?.protocol,
    activeInsecureWithoutPin: activeProfile?.insecureWithoutPin
  });

  const runCheck = async (): Promise<void> => {
    setRequested(true);
    await run(() => api.checkTunnel(), { errorTitle: "Couldn't run the tunnel check", background: true });
    setRequested(false);
  };

  const tone = BADGE_TONE[view.kind];
  return (
    <Card rise={3} aria-label="Tunnel check" aria-live="polite" className="cn-check">
      <CardHeader
        icon={Radar}
        title="Tunnel check"
        sub={
          <>
            Sends a test request through the tunnel to <span className="mono">{endpoint}</span>
          </>
        }
        tools={<IconButton icon={Pencil} label="Change check endpoint" tooltip="Change endpoint" onClick={() => setDialogOpen(true)} />}
      />

      <div className="row-wrap">
        <Badge tone={tone} spinner={view.kind === "checking"} dot={view.kind !== "checking"}>
          {view.badge}
        </Badge>
        {view.kind === "note" ? <Badge tone="outline">With a note</Badge> : null}
      </div>

      {view.kind === "checking" ? <Progress label="Tunnel check in progress" /> : null}

      <p className="cn-check-text anim-swap" key={view.kind}>
        <Segments segments={view.text} />
      </p>

      {view.steps ? (
        <div className="stack-sm">
          {view.stepsIntro ? <span className="muted cn-steps-intro">{view.stepsIntro}</span> : null}
          <ul className="cn-steps">
            {view.steps.map((step, index) => (
              <li key={index}>
                <span>
                  <Segments segments={step} />
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {view.kind === "note" ? (
        <Callout
          tone="info"
          icon={Info}
          actions={
            <LinkButton onClick={() => setDialogOpen(true)}>Change endpoint</LinkButton>
          }
        >
          For a full check, use a TLS or HTTP endpoint such as <span className="mono">{DEFAULT_CHECK_ENDPOINT}</span>.
        </Callout>
      ) : null}

      {view.meta ? <span className="cn-check-meta">{view.meta}</span> : null}

      <div className="cn-check-foot">
        <Button size="sm" icon={RefreshCw} busy={checking} busyLabel="Checking…" disabled={!connected} onClick={() => void runCheck()}>
          Run check
        </Button>
        {view.kind === "waiting" ? <span className="hint">Available while connected</span> : null}
        {view.kind === "failed" ? (
          <Button variant="ghost" size="sm" onClick={() => setDialogOpen(true)}>
            Change endpoint
          </Button>
        ) : null}
      </div>

      <EndpointDialog open={dialogOpen} current={endpoint} onClose={() => setDialogOpen(false)} />
    </Card>
  );
}
