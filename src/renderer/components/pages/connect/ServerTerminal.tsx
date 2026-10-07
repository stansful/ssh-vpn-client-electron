import { ChevronDown, RotateCcw, Terminal, TriangleAlert } from "lucide-react";
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type FormEvent } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import { formatClock } from "../../../lib/format.js";
import { Badge, Button, Callout, Collapse, Icon, Kbd, cx, type Tone } from "../../ui/index.js";
import { shellFailureCopy } from "./connect-copy.js";
import { resolveTarget } from "./connect-target.js";
import { buildTerminalDisplay, isPromptLine, type TerminalDisplayLine, type TerminalState } from "./terminal-view.js";
import { useServerShell } from "./useServerShell.js";

const BADGE: Record<TerminalState, { tone: Tone; text: string; spinner?: boolean }> = {
  offline: { tone: "neutral", text: "Offline" },
  idle: { tone: "ok", text: "Live" },
  opening: { tone: "busy", text: "Opening…", spinner: true },
  live: { tone: "ok", text: "Live" },
  closed: { tone: "warn", text: "Shell closed" },
  failed: { tone: "danger", text: "No shell" }
};

const PLACEHOLDER: Record<TerminalState, string> = {
  offline: "Connect to use the terminal",
  idle: "Type a command and press Enter",
  opening: "Opening a shell…",
  live: "Type a command and press Enter",
  closed: "Reopen the shell to type commands",
  failed: "Retry to open a shell"
};

const LINE_MODE_NOTE = "Line mode: each line is sent on Enter. Ctrl+C, Tab completion and full-screen apps like vim or top aren’t supported.";

/** Distance from the bottom (px) that still counts as following the output. */
const FOLLOW_THRESHOLD = 24;

/**
 * SSH only: a line-mode shell over the encrypted session. Each state says
 * whether typing reaches the server; collapsing or Close shell ends the shell,
 * never the tunnel.
 */
export function ServerTerminal(): JSX.Element {
  const { snapshot, runtime, activeTransport } = useAppData();
  const shell = useServerShell();
  const bodyId = useId();
  const inputId = useId();
  const logRef = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  const [command, setCommand] = useState("");

  const target = resolveTarget(snapshot, "ssh").target;
  const name = runtime.activeConfigName && activeTransport === "ssh" ? runtime.activeConfigName : target?.name ?? "your server";
  const username = target?.config?.username;
  const { state } = shell;
  const canType = state === "live";

  // Remember when the SSH session ended, for the note under the old output.
  const live = activeTransport === "ssh" && runtime.state === "Connected";
  const [endedAt, setEndedAt] = useState<string>();
  const wasLive = useRef(live);
  useEffect(() => {
    if (wasLive.current && !live) {
      setEndedAt(new Date().toISOString());
    }
    if (live) {
      setEndedAt(undefined);
    }
    wasLive.current = live;
  }, [live]);

  const display = useMemo(() => buildTerminalDisplay(snapshot.terminal), [snapshot.terminal]);
  const lines = useMemo<TerminalDisplayLine[]>(() => {
    const rows: TerminalDisplayLine[] = [];
    if (display.truncated) {
      rows.push({ text: "Older output is hidden here. The newest lines are shown.", cls: "t-dim" });
    }
    if (state === "offline") {
      if (display.lines.length === 0) {
        rows.push({ text: "Shell is offline.", cls: "t-dim" }, { text: `Connect to ${name} to open an interactive shell here.`, cls: "t-dim" });
        return rows;
      }
      rows.push(...display.lines.map((line) => ({ ...line, cls: cx(line.cls, "cn-old") })));
      rows.push({
        text: `${endedAt ? `Session ended at ${formatClock(endedAt)}. ` : ""}This output stays until your next connect.`,
        cls: "t-dim"
      });
      return rows;
    }
    rows.push(...display.lines);
    if (state === "live" && rows.length > 0 && isPromptLine(rows[rows.length - 1].text) && rows[rows.length - 1].cls === "") {
      rows[rows.length - 1] = { ...rows[rows.length - 1], cls: "t-ok" };
    }
    if (state === "opening" && display.lines.length === 0) {
      rows.push({ text: `Opening a shell on ${name}…`, cls: "t-dim" });
    }
    if (state === "failed") {
      rows.push(
        { text: `Opening a shell on ${name}…`, cls: "t-dim" },
        { text: shell.error ?? "The shell didn’t open.", cls: "t-err" },
        { text: "No shell is open, so nothing you type would reach the server.", cls: "t-dim" }
      );
    }
    return rows;
  }, [display, endedAt, name, shell.error, state]);

  // Follow new output unless the person scrolled up to read.
  const lastLine = lines.length > 0 ? lines[lines.length - 1].text : "";
  useLayoutEffect(() => {
    const log = logRef.current;
    if (log && follow.current) {
      log.scrollTop = log.scrollHeight;
    }
  }, [lines.length, lastLine, shell.expanded]);

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (!canType || !command.trim()) {
      return;
    }
    shell.send(command);
    setCommand("");
    follow.current = true;
  };

  const badge = BADGE[state];
  const showFooter = state === "offline" || state === "opening" || state === "live" || state === "idle";

  return (
    <section className="card rise cn-term" style={{ "--d": 5 } as CSSProperties} aria-label="Server terminal">
      <button
        type="button"
        className="cn-term-head"
        aria-expanded={shell.expanded}
        aria-controls={bodyId}
        data-open={shell.expanded ? "true" : "false"}
        onClick={() => shell.setExpanded(!shell.expanded)}
      >
        <span className="card-icon">
          <Icon icon={Terminal} />
        </span>
        <span className="cn-term-titles">
          <span className="card-title">Server terminal</span>
          <span className="card-sub">Run commands on {name} over the encrypted session</span>
        </span>
        <Badge tone={badge.tone} dot={!badge.spinner} spinner={badge.spinner}>
          {badge.text}
        </Badge>
        <Icon icon={ChevronDown} className="chev faint" />
      </button>

      <Collapse open={shell.expanded} id={bodyId}>
        <div className="stack cn-term-body">
          <div
            ref={logRef}
            className="term term-lines"
            role="log"
            aria-label="Terminal output"
            tabIndex={0}
            onScroll={(event) => {
              const element = event.currentTarget;
              follow.current = element.scrollHeight - element.scrollTop - element.clientHeight < FOLLOW_THRESHOLD;
            }}
          >
            {lines.map((line, index) => (
              <span key={index} className={cx("term-line", line.cls)}>
                {line.text}
              </span>
            ))}
          </div>

          {state === "closed" ? (
            <Callout
              icon={Terminal}
              title="The server closed this shell"
              actions={
                <Button variant="primary" size="sm" icon={RotateCcw} onClick={shell.reopen}>
                  Reopen shell
                </Button>
              }
            >
              Usually after exit or logout. The tunnel is still up.
            </Callout>
          ) : null}

          {state === "failed" ? (
            <Callout
              tone="danger"
              icon={TriangleAlert}
              title="Couldn’t open a shell"
              actions={
                <Button size="sm" icon={RotateCcw} onClick={shell.reopen}>
                  Retry
                </Button>
              }
            >
              {shellFailureCopy(shell.error ?? "", { name, username })}
            </Callout>
          ) : null}

          <form className="term-input" onSubmit={submit}>
            <span className="t-prompt" aria-hidden="true">
              $
            </span>
            <label className="sr-only" htmlFor={inputId}>
              Command
            </label>
            <input
              id={inputId}
              type="text"
              value={command}
              placeholder={PLACEHOLDER[state]}
              disabled={!canType}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              onChange={(event) => setCommand(event.target.value)}
            />
            <Button type="submit" size="sm" disabled={!canType}>
              Send
              <Kbd>↵</Kbd>
            </Button>
          </form>

          {showFooter ? (
            <div className="row-wrap cn-term-foot">
              <span className="hint">{state === "offline" ? `Connect to ${name} and a fresh shell opens here.` : LINE_MODE_NOTE}</span>
              <Button
                variant="ghost"
                size="sm"
                busy={state === "opening" || shell.closing}
                disabled={state !== "live"}
                onClick={shell.closeAndCollapse}
              >
                Close shell
              </Button>
            </div>
          ) : null}
        </div>
      </Collapse>
    </section>
  );
}
