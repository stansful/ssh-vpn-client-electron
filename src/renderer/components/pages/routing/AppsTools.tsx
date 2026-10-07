import { AppWindow, ArrowRight, Check, ChevronDown, Info, Network, RefreshCw, RotateCcw, X } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import type { DesktopPlatform, RoutingRule } from "../../../../shared/types.js";
import {
  Badge,
  Button,
  Collapse,
  DisclosureButton,
  Icon,
  IconTile,
  Mono,
  SearchInput,
  Skeleton,
  StatusDot,
  Switch
} from "../../ui/index.js";
import { presentTun, processChips, processFootText } from "./routing-model.js";
import type { RoutingController } from "./useRoutingController.js";

/** Windows: capture app traffic with the TUN adapter, with live status and a requirements checklist. */
export function TunCard({ ctl }: { ctl: RoutingController }): JSX.Element {
  const { snapshot } = useAppData();
  const [howOpen, setHowOpen] = useState(false);
  const tun = { ...snapshot.tunStatus, enabled: ctl.tunEnabled };
  const view = presentTun(tun, ctl.live);
  const pending = snapshot.tunStatus.appliesOnNextConnect && snapshot.runtime.state === "Connected";
  const tone = view.tone === "off" ? "neutral" : view.tone;
  const open = howOpen && ctl.tunEnabled;

  return (
    <div className="rt-tun">
      <div className="rt-tun-top">
        <IconTile icon={Network} tone={tone} />
        <div className="toggle-copy">
          <span className="toggle-title">Capture all app traffic with the TUN adapter</span>
          <span className="toggle-desc">
            Some apps ignore the Windows proxy: Telegram, Discord voice, browsers using QUIC. A TUN adapter catches their traffic too. Applies
            to every mode and rule type. Windows only.
          </span>
        </div>
        <Switch checked={ctl.tunEnabled} aria-label="Capture all app traffic with the TUN adapter" onCheckedChange={ctl.toggleTun} />
      </div>

      <div className="rt-tun-status anim-swap" key={`${ctl.tunEnabled}-${view.title}`} data-tone={view.tone} role="status">
        <StatusDot tone={tone} />
        <div className="rt-tun-status-copy">
          <span className="rt-tun-status-title">{view.title}</span>
          <span className="hint">{view.sub}</span>
        </div>
        <div className="rt-tun-actions">
          {pending ? (
            <>
              <Badge tone="warn">Applies on next connect</Badge>
              <Button size="sm" icon={RotateCcw} busy={ctl.reconnecting} busyLabel="Reconnecting…" onClick={() => void ctl.reconnectNow()}>
                Reconnect now
              </Button>
            </>
          ) : null}
          {ctl.tunEnabled ? (
            <DisclosureButton open={open} controls="rt-how" onClick={() => setHowOpen((current) => !current)}>
              {view.howLabel}
            </DisclosureButton>
          ) : null}
        </div>
      </div>

      <Collapse id="rt-how" open={open}>
        <ol className="rt-steps">
          <Step ok={view.dllOk} title={<><Mono>wintun.dll</Mono> is in place</>} badge={view.dllOk ? "Found" : "Missing"}>
            Put it next to <Mono>Shadow SSH.exe</Mono> or in the app data folder, beside the logs.
            {snapshot.tunStatus.searchedPaths.length > 0 ? <> Shadow SSH looks in {pathList(snapshot.tunStatus.searchedPaths)}.</> : null}
          </Step>
          <Step ok={view.adminOk} title="Running as administrator" badge={view.adminOk ? "Yes" : "No"}>
            Right-click Shadow SSH and choose <strong>Run as administrator</strong>. Being signed in to Windows as an administrator isn’t the same
            thing.
          </Step>
          <li className="rt-step">
            <span className="rt-step-ic" data-ok="next">
              <Icon icon={ArrowRight} />
            </span>
            <span className="rt-step-copy">
              <span className="rt-step-title">Reconnect</span>
              <span className="hint">The adapter starts with the next connection. If something is still missing, Activity says what.</span>
            </span>
          </li>
        </ol>
      </Collapse>
    </div>
  );
}

function pathList(paths: readonly string[]): ReactNode {
  return paths.map((path, index) => (
    <span key={path}>
      {index > 0 ? (index === paths.length - 1 ? " and " : ", ") : null}
      <Mono>{path}</Mono>
    </span>
  ));
}

function Step({ ok, title, badge, children }: { ok: boolean; title: ReactNode; badge: string; children: ReactNode }): JSX.Element {
  return (
    <li className="rt-step">
      <span className="rt-step-ic" data-ok={ok}>
        <Icon icon={ok ? Check : X} />
      </span>
      <span className="rt-step-copy">
        <span className="rt-step-title">
          {title}{" "}
          <Badge square tone={ok ? "ok" : "warn"}>
            {badge}
          </Badge>
        </span>
        <span className="hint">{children}</span>
      </span>
    </li>
  );
}

export type ProcessLoad = { state: "idle" } | { state: "loading"; previous?: string[] } | { state: "loaded"; names: string[] };

const SKELETON_WIDTHS = [104, 86, 120, 92, 140, 78, 110, 96, 128];

/** Running apps to pick from instead of typing names (Apps tab). */
export function RunningApps({
  load,
  onLoad,
  query,
  onQueryChange,
  appRules,
  platform,
  onPick
}: {
  load: ProcessLoad;
  onLoad: () => void;
  query: string;
  onQueryChange: (value: string) => void;
  appRules: readonly RoutingRule[];
  platform: DesktopPlatform;
  onPick: (name: string) => void;
}): JSX.Element {
  const searchId = useId();
  const loading = load.state === "loading";
  const names = load.state === "loaded" ? load.names : [];
  const { chips, matches } = processChips(names, query, appRules, platform);
  const trimmed = query.trim();

  return (
    <div className="rt-procs">
      <div className="rt-procs-head">
        <div className="rt-procs-copy">
          <span className="label">Running apps</span>
          <span className="hint">Pick one to fill the field above. It’s added when you press Add.</span>
        </div>
        <div className="rt-procs-tools">
          <div className="rt-search">
            <SearchInput
              id={searchId}
              value={query}
              onValueChange={onQueryChange}
              placeholder="Search running apps"
              aria-label="Search running apps"
              disabled={load.state !== "loaded"}
              autoComplete="off"
            />
          </div>
          <Button size="sm" icon={RefreshCw} busy={loading} aria-label="Refresh running apps" title="Refresh running apps" onClick={onLoad}>
            Refresh
          </Button>
        </div>
      </div>

      {load.state === "idle" ? (
        <div className="rt-procs-empty fade">
          <span className="empty-icon" aria-hidden="true">
            <Icon icon={AppWindow} />
          </span>
          <span className="hint">See what’s running right now and pick from it instead of typing names. Takes up to 5 s.</span>
          <Button size="sm" onClick={onLoad}>
            Load running apps
          </Button>
        </div>
      ) : null}

      {loading ? (
        <div className="chips" aria-hidden="true">
          {SKELETON_WIDTHS.map((width, index) => (
            <Skeleton key={index} width={width} height={30} className="rt-skel" />
          ))}
        </div>
      ) : null}

      {load.state === "loaded" && chips.length > 0 ? (
        <div className="chips rt-chips fade" role="group" aria-label="Running apps">
          {chips.map((chip) => (
            <button
              key={chip.name}
              type="button"
              className="chip"
              data-added={chip.added}
              aria-disabled={chip.added}
              aria-label={chip.added ? `${chip.name}, already in your rules` : `Use ${chip.name} in the new rule`}
              onClick={() => {
                if (!chip.added) {
                  onPick(chip.name);
                }
              }}
            >
              {chip.name}
              {chip.added ? <Icon icon={Check} /> : null}
            </button>
          ))}
        </div>
      ) : null}

      {load.state === "loaded" && chips.length === 0 ? (
        <span className="hint">
          {names.length === 0
            ? "Shadow SSH couldn’t see any running apps. Type the name above instead."
            : `No running app matches “${trimmed}”. Type the name above instead.`}
        </span>
      ) : null}

      {load.state === "loaded" && names.length > 0 ? <span className="hint">{processFootText(names.length, matches, query)}</span> : null}
    </div>
  );
}

/** Collapsible note about what app rules can and can't carry. */
export function UdpNote(): JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <div className="rt-note">
      <button
        type="button"
        className="rt-note-head"
        aria-expanded={open}
        aria-controls="rt-udp"
        data-open={open}
        onClick={() => setOpen((current) => !current)}
      >
        <Icon icon={Info} size="sm" className="rt-note-ic" />
        About UDP and QUIC
        <Icon icon={ChevronDown} size="sm" className="chev" />
      </button>
      <Collapse id="rt-udp" open={open}>
        <div className="rt-note-body">
          <p>An app rule sends every TCP connection that app makes through the tunnel. UDP depends on the transport: Xray carries it, SSH can’t.</p>
          <p>
            Apps that use QUIC, like browsers reaching Google, switch to TCP when UDP isn’t available, so their traffic still enters the tunnel.
            Ping doesn’t go through the TUN adapter.
          </p>
          <p>Hysteria 2 profiles need UDP themselves: they reach the server over QUIC, so they can’t carry anything on a network that blocks UDP.</p>
        </div>
      </Collapse>
    </div>
  );
}
