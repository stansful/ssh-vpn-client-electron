import { AppWindow, Filter, Globe, List, Network, Route, ShieldCheck, TriangleAlert, type LucideIcon } from "lucide-react";
import { useRef, type KeyboardEvent } from "react";
import { plural } from "../../../lib/format.js";
import type { RoutingMode } from "../../../../shared/types.js";
import { Badge, Card, CardHeader, Icon } from "../../ui/index.js";
import { summaryCopy } from "./routing-model.js";
import type { RoutingController } from "./useRoutingController.js";

const MODES: readonly RoutingMode[] = ["proxy-all", "selected-rules"];

/** Mode switch (Full / Split tunnel) with a live flow diagram, and what Split tunnel would send. */
export function ModeCard({ ctl }: { ctl: RoutingController }): JSX.Element {
  const { mode, targets, connection, steers } = ctl;
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  const summary = summaryCopy(mode, targets);
  const blocked = mode === "selected-rules" && targets.total === 0;

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    const keys: Record<string, number> = {
      ArrowRight: index + 1,
      ArrowDown: index + 1,
      ArrowLeft: index - 1,
      ArrowUp: index - 1,
      Home: 0,
      End: MODES.length - 1
    };
    if (!(event.key in keys)) {
      return;
    }
    event.preventDefault();
    const next = (keys[event.key] + MODES.length) % MODES.length;
    buttons.current[next]?.focus();
    ctl.pickMode(MODES[next]);
  }

  const option = (value: RoutingMode, index: number, name: string, tag: string, icon: LucideIcon, description: string, extra?: JSX.Element): JSX.Element => {
    const checked = mode === value;
    return (
      <button
        ref={(element) => {
          buttons.current[index] = element;
        }}
        type="button"
        className="rt-mode"
        role="radio"
        aria-checked={checked}
        tabIndex={checked ? 0 : -1}
        onClick={() => ctl.pickMode(value)}
        onKeyDown={(event) => handleKeyDown(event, index)}
      >
        <span className="rt-mode-top">
          <span className="rt-mode-icon">
            <Icon icon={icon} size="lg" />
          </span>
          <span className="rt-mode-head">
            <span className="rt-mode-name">{name}</span>
            <span className="rt-mode-tag">{tag}</span>
          </span>
          <span className="rt-radio" aria-hidden="true" />
        </span>
        <span className="rt-flow-wrap">
          <FlowDiagram split={value === "selected-rules"} />
        </span>
        <span className="rt-mode-desc">{description}</span>
        {extra}
      </button>
    );
  };

  return (
    <Card rise={1} aria-labelledby="rt-mode-title">
      <CardHeader
        level={2}
        titleId="rt-mode-title"
        icon={Route}
        title="Mode"
        sub="Pick what the tunnel carries. You can switch at any time."
        tools={
          <Badge tone={connection.tone} spinner={connection.spinner} dot={!connection.spinner}>
            {connection.text}
          </Badge>
        }
      />

      <div className="rt-modes" role="radiogroup" aria-label="Traffic mode">
        {option(
          "proxy-all",
          0,
          "Full tunnel",
          steers ? "Everything is protected" : "Everything sent to the proxy",
          ShieldCheck,
          "All traffic goes through the tunnel. Sites on the Russian services list stay direct when the system proxy is used."
        )}
        {option(
          "selected-rules",
          1,
          "Split tunnel",
          "Only what you choose",
          Filter,
          "Only what you add below goes through the tunnel. Everything else stays direct.",
          targets.total === 0 ? (
            <Badge tone="warn" icon={TriangleAlert} className="rt-mode-flag">
              Nothing to route yet
            </Badge>
          ) : undefined
        )}
      </div>

      <div className="rt-summary anim-swap" key={`${mode}-${blocked ? "z" : "n"}`} data-tone={summary.tone || undefined} aria-live="polite">
        <span className="rt-total">{targets.total}</span>
        <span className="rt-total-copy">
          <span className="rt-total-title">{summary.title}</span>
          <span className="hint">{summary.sub}</span>
        </span>
        <span className="rt-parts">
          <SummaryPart icon={Globe} count={targets.domains} text={plural(targets.domains, "domain")} />
          <SummaryPart icon={Network} count={targets.ips} text={plural(targets.ips, "IP")} />
          <SummaryPart icon={AppWindow} count={targets.apps} text={plural(targets.apps, "app")} />
          <SummaryPart icon={List} count={targets.lists} text={plural(targets.lists, "list")} />
        </span>
      </div>
    </Card>
  );
}

function SummaryPart({ icon, count, text }: { icon: LucideIcon; count: number; text: string }): JSX.Element {
  return (
    <span className="rt-part" data-zero={count === 0}>
      <Icon icon={icon} />
      {text}
    </span>
  );
}

/** Three sources flowing into Tunnel / Direct; the selected mode animates its tunnel paths. */
function FlowDiagram({ split }: { split: boolean }): JSX.Element {
  return (
    <svg className="rt-flow" viewBox="0 0 260 64" preserveAspectRatio="xMinYMid meet" aria-hidden="true" focusable="false">
      <path className="p p-t" d="M16 12 C 96 12, 112 16, 188 16" />
      {split ? (
        <>
          <path className="p p-d" d="M16 32 C 96 32, 112 48, 188 48" />
          <path className="p p-d" d="M16 52 C 96 52, 112 48, 188 48" />
        </>
      ) : (
        <>
          <path className="p p-t" d="M16 32 C 96 32, 112 16, 188 16" />
          <path className="p p-t" d="M16 52 C 96 52, 112 16, 188 16" />
          <path className="p p-x" d="M16 52 C 96 52, 112 48, 188 48" />
        </>
      )}
      <circle className="src" cx="12" cy="12" r="3.5" />
      <circle className="src" cx="12" cy="32" r="3.5" />
      <circle className="src" cx="12" cy="52" r="3.5" />
      <circle className="halo" cx="196" cy="16" r="11" />
      <circle className="n n-t" cx="196" cy="16" r="6" />
      <circle className="n n-d" cx="196" cy="48" r="6" />
      <text className="t-t" x="210" y="19.5">
        Tunnel
      </text>
      <text x="210" y="51.5">
        Direct
      </text>
    </svg>
  );
}
