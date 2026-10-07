import { Check, ClipboardPaste, Globe, Link, Pin, RefreshCw, Trash2, TriangleAlert, type LucideIcon } from "lucide-react";
import { memo, useId, useMemo, type CSSProperties } from "react";
import type { ProxyProfile, ProxyProfileSource } from "../../../../shared/types.js";
import { Badge, cx, Icon, IconButton, Spinner, StatusDot } from "../../ui/index.js";
import { presentProfileCard, sourceLabel, sourceTitle, type XraySession } from "./profile-presenter.js";

const SOURCE_ICON: Record<ProxyProfileSource, LucideIcon> = {
  remote: Globe,
  clipboard: ClipboardPaste,
  manual: Link
};

export interface ProfileCardProps {
  profile: ProxyProfile;
  /** Connect uses this profile (next time, if another one runs now). */
  selected: boolean;
  /** The running Xray session, if any. */
  session?: XraySession;
  /** Position in the grid, for the entrance stagger. */
  index: number;
  /** Playing its removal animation. */
  leaving: boolean;
  onSelect: (profile: ProxyProfile) => void;
  onTogglePin: (profile: ProxyProfile) => void;
  onRemove: (profile: ProxyProfile) => void;
}

/**
 * One profile. The whole card is the select button (`.pf-hit` under the
 * content); Pin and Remove sit on top of it in the footer.
 */
export const ProfileCard = memo(function ProfileCard({ profile, selected, session, index, leaving, onSelect, onTogglePin, onRemove }: ProfileCardProps): JSX.Element {
  const view = useMemo(() => presentProfileCard(profile, { selectedId: selected ? profile.id : undefined, session }), [profile, selected, session]);
  const { state } = view;
  const insecureId = useId();
  return (
    <div className="pf-cell rise" style={{ "--d": 3 + Math.min(index, 9) } as CSSProperties} data-leaving={leaving ? "true" : undefined}>
      <article
        className="pf-card"
        aria-label={profile.name}
        data-selected={view.selected ? "true" : "false"}
        data-inuse={view.inUse ? "true" : "false"}
        data-gone={profile.isStale ? "true" : "false"}
        data-bad={view.unsupported ? "true" : "false"}
      >
        <button
          type="button"
          className="pf-hit"
          title={view.hitTitle}
          aria-pressed={view.selected}
          aria-disabled={view.unsupported ? true : undefined}
          aria-label={view.hitLabel}
          aria-describedby={view.insecure ? insecureId : undefined}
          onClick={() => onSelect(profile)}
        />
        <div className="pf-body">
          <div className="pf-head">
            <Badge square tone={view.protoTone}>{view.protocol}</Badge>
            <span className="pf-name truncate" title={profile.name}>
              {profile.name}
            </span>
            {view.badge ? (
              <Badge tone={view.badge.tone} dot={view.badge.glyph === "dot"} spinner={view.badge.glyph === "spinner"}>
                {view.badge.text}
              </Badge>
            ) : null}
          </div>
          <span className="pf-addr mono truncate" title={view.address}>
            {view.address}
          </span>
          <div className="pf-tags">
            <span className={cx("pf-tag", view.transportBad && "is-bad")} title="Transport">
              {view.transport}
            </span>
            <span className={cx("pf-tag", view.securityBad && "is-bad")} title="Security">
              {view.security}
            </span>
            {view.insecure ? (
              <span className="pf-tag is-bad" title={view.insecure.text}>
                {view.insecure.tag}
                <span className="sr-only" id={insecureId}>
                  {view.insecure.text}
                </span>
              </span>
            ) : null}
            <span className={cx("pf-src", profile.source === "remote" && "is-public")} title={sourceTitle(profile.source)}>
              <Icon icon={SOURCE_ICON[profile.source]} />
              {sourceLabel(profile.source)}
            </span>
          </div>
          {view.goneText ? (
            <div className="pf-note anim-swap">
              <Badge tone="warn" icon={RefreshCw}>
                Gone from source
              </Badge>
              <span>{view.goneText}</span>
            </div>
          ) : null}
          {view.unsupported ? (
            <div className="pf-note is-warn">
              <Badge tone="warn" icon={TriangleAlert}>
                {view.unsupported.label}
              </Badge>
              <span>{view.unsupported.text}</span>
            </div>
          ) : null}
        </div>
        <div className="pf-foot">
          {state ? (
            <span key={`${profile.id}-${state.label}`} className={cx("pf-state anim-swap", `is-${state.tone}`)}>
              {state.glyph === "dot" ? <StatusDot tone={state.tone === "warn" ? "warn" : "ok"} /> : state.glyph === "spinner" ? <Spinner /> : <Icon icon={Check} />}
              <span className="truncate">{state.label}</span>
            </span>
          ) : (
            <span className="pf-state pf-hint">
              <span className="truncate">{view.hint}</span>
            </span>
          )}
          <button type="button" className="pf-pin" aria-pressed={profile.isPinned} title={view.pinTitle} onClick={() => onTogglePin(profile)}>
            <span className="pf-pin-ic" key={profile.isPinned ? "on" : "off"}>
              <Icon icon={Pin} />
            </span>
            <span>{view.pinLabel}</span>
            <span className="sr-only">{profile.name}</span>
          </button>
          <IconButton
            icon={Trash2}
            label={view.removeLabel}
            tooltip={view.removeTitle}
            className="pf-del"
            aria-disabled={view.removeBlocked || undefined}
            onClick={() => onRemove(profile)}
          />
        </div>
      </article>
    </div>
  );
});
