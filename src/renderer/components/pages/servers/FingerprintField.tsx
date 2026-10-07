import { BadgeCheck, Check, CircleAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { useId } from "react";
import { Badge, Button, Icon, StateLine, TextInput } from "../../ui/index.js";
import type { FingerprintAnalysis, PinState } from "./server-form-model.js";

/** Badge at the right of the Security group heading. */
export function PinBadge({ state }: { state: PinState }): JSX.Element {
  switch (state) {
    case "pinned":
      return (
        <Badge tone="ok" icon={ShieldCheck}>
          Pinned
        </Badge>
      );
    case "will-pin":
      return (
        <Badge tone="accent" className="anim-swap">
          Pins on save
        </Badge>
      );
    case "will-unpin":
      return (
        <Badge tone="warn" className="anim-swap">
          Unpins on save
        </Badge>
      );
    default:
      return <Badge tone="outline">Not pinned</Badge>;
  }
}

export interface FingerprintFieldProps {
  id: string;
  value: string;
  onChange: (value: string) => void;
  /** The field lost focus or was pasted into: errors may show. */
  onReveal: () => void;
  analysis: FingerprintAnalysis;
  /** Message to show (live analysis once revealed, or the core's rejection). */
  error?: string;
  pin: PinState;
  /** Server name for "… will be pinned to this key when you save." */
  serverName: string;
  /** Host key the running session verified, offered when nothing is pinned. */
  suggestion?: string;
  /** "your PC" / "your Mac" / "your computer". */
  device: string;
}

/** Host key fingerprint with quick fixes, pin preview and the trust-on-first-use suggestion. */
export function FingerprintField({ id, value, onChange, onReveal, analysis, error, pin, serverName, suggestion, device }: FingerprintFieldProps): JSX.Element {
  const ids = useId();
  const messageId = `${ids}-msg`;
  const hintId = `${ids}-hint`;
  const showSuggestion = Boolean(suggestion) && !value.trim();
  const hasMessage = Boolean(error) || pin === "will-pin" || pin === "will-unpin" || showSuggestion;

  return (
    <div className="field">
      <label className="label" htmlFor={id}>
        Host key fingerprint <span className="opt">optional</span>
      </label>
      <TextInput
        id={id}
        icon={BadgeCheck}
        mono
        value={value}
        placeholder="SHA256:…"
        autoComplete="off"
        autoCapitalize="off"
        invalid={Boolean(error)}
        aria-describedby={[hasMessage ? messageId : undefined, hintId].filter(Boolean).join(" ")}
        onChange={(event) => onChange(event.target.value)}
        onBlur={onReveal}
        onPaste={() => window.setTimeout(onReveal, 0)}
      />
      {error ? (
        <div className="fm-err" id={messageId} role="alert">
          <div className="error-text">
            <Icon icon={CircleAlert} size="sm" />
            <span>{error}</span>
          </div>
          {analysis.fix ? (
            <Button size="sm" onClick={() => analysis.fix && onChange(analysis.fix.value)}>
              {analysis.fix.label}
            </Button>
          ) : null}
        </div>
      ) : pin === "will-pin" ? (
        <StateLine tone="ok" icon={Check} id={messageId}>
          <b>Looks right.</b> {serverName} will be pinned to this key when you save.
        </StateLine>
      ) : pin === "will-unpin" ? (
        <StateLine tone="warn" icon={TriangleAlert} id={messageId}>
          <b>Saving removes the pin.</b> {serverName} will accept any host key again.
        </StateLine>
      ) : showSuggestion && suggestion ? (
        <div className="fm-suggest anim-swap" id={messageId}>
          <div className="fm-suggest-top">
            <Icon icon={BadgeCheck} size="sm" />
            <div>
              <b>Your last connection saw this key</b>
              <span className="fm-suggest-fp">{suggestion}</span>
            </div>
          </div>
          <div className="fm-row-between">
            <span className="hint">Pin it only if you trust the network you connected from.</span>
            <Button size="sm" onClick={() => onChange(suggestion)}>
              Pin this key
            </Button>
          </div>
        </div>
      ) : null}
      <p className="hint" id={hintId}>
        A pinned server must present this exact key, or Shadow SSH stops instead of retrying. Pinning also helps when DNS fails, say right after {device}{" "}
        wakes up: a pinned server can reconnect through its last known IP. Get it on the server with{" "}
        <span className="fm-cmd">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span>
      </p>
    </div>
  );
}
