import { ArrowRight, BadgeCheck, Check, Clock, KeyRound, Lock, Pencil, Trash2, TriangleAlert } from "lucide-react";
import { useEffect, useRef, type CSSProperties } from "react";
import { initials } from "../../../lib/format.js";
import { Badge, Button, Icon, IconButton } from "../../ui/index.js";
import { serverAddress, serverSignIn, type SshSessionView } from "./server-model.js";
import type { SshConfig, SshKeyMetadata } from "../../../../shared/types.js";

/** "Connected" / "Connecting…" / "Reconnecting…" for the server the session runs on. */
export function LiveBadge({ state, className }: { state: SshSessionView["state"]; className?: string }): JSX.Element | null {
  if (state === "connected") {
    return (
      <Badge tone="ok" dot className={className}>
        Connected
      </Badge>
    );
  }
  if (state === "preview") {
    return (
      <Badge tone="warn" dot className={className} title="Shadow SSH couldn’t start its connection core, so this session routes nothing">
        Preview only
      </Badge>
    );
  }
  if (state === "connecting" || state === "reconnecting") {
    return (
      <Badge tone="busy" spinner className={className}>
        {state === "connecting" ? "Connecting…" : "Reconnecting…"}
      </Badge>
    );
  }
  return null;
}

export interface ServerRowProps {
  config: SshConfig;
  keys: readonly SshKeyMetadata[];
  /** Position in the list, for the entrance stagger. */
  index: number;
  selected: boolean;
  /** Session state when the session runs on this server. */
  live?: SshSessionView["state"];
  /** An SSH session runs (on any server), so a new pick applies on the next connect. */
  sessionOn: boolean;
  leaving: boolean;
  /** Move focus to "Used by Connect" once this row becomes the selected one. */
  focusWhenSelected: boolean;
  onUse: () => void;
  onEdit: (focus?: "password" | "key") => void;
  onDelete: () => void;
  onOpenKeys: () => void;
}

export function ServerRow({
  config,
  keys,
  index,
  selected,
  live,
  sessionOn,
  leaving,
  focusWhenSelected,
  onUse,
  onEdit,
  onDelete,
  onOpenKeys
}: ServerRowProps): JSX.Element {
  const currentRef = useRef<HTMLSpanElement>(null);
  const signIn = serverSignIn(config, keys);
  const name = config.name || "Unnamed server";

  useEffect(() => {
    if (selected && focusWhenSelected) {
      currentRef.current?.focus({ preventScroll: true });
    }
  }, [focusWhenSelected, selected]);

  return (
    <div className="sv-slot" role="listitem" data-leaving={leaving ? "true" : "false"} aria-hidden={leaving || undefined}>
      <div>
        <article
          className="sv-row rise"
          style={{ "--d": Math.min(index + 2, 12) } as CSSProperties}
          data-selected={selected ? "true" : "false"}
          aria-label={name}
        >
          <span className="sv-ava" aria-hidden="true">
            {initials(name)}
            {live === "connected" ? <span className="sv-live" /> : null}
          </span>

          <div className="sv-main">
            <div className="sv-title">
              <h3 className="sv-name">{name}</h3>
              <LiveBadge state={live} />
            </div>
            <span className="sv-addr">{serverAddress(config)}</span>
            <div className="sv-meta">
              {signIn.kind === "password" ? (
                <>
                  <span className="sv-pill" title="Signs in with a password">
                    <Icon icon={Lock} />
                    Password
                  </span>
                  {!signIn.saved ? (
                    <>
                      <Badge tone="warn" icon={TriangleAlert} title="Connecting will fail until you add a password">
                        No password saved
                      </Badge>
                      <button type="button" className="link-btn sv-fix" aria-label={`Add a password for ${name}`} onClick={() => onEdit("password")}>
                        Add password
                        <Icon icon={ArrowRight} />
                      </button>
                    </>
                  ) : null}
                </>
              ) : signIn.key ? (
                <button type="button" className="sv-pill" aria-label={`Signs in with key ${signIn.key.name}. Open SSH keys`} title="Open SSH keys" onClick={onOpenKeys}>
                  <Icon icon={KeyRound} />
                  Key · <span className="mono">{signIn.key.name}</span>
                </button>
              ) : (
                <>
                  <Badge tone="warn" icon={TriangleAlert} title="Connecting will fail until you pick a key">
                    No key chosen
                  </Badge>
                  <button type="button" className="link-btn sv-fix" aria-label={`Choose a key for ${name}`} onClick={() => onEdit("key")}>
                    Choose a key
                    <Icon icon={ArrowRight} />
                  </button>
                </>
              )}
              {config.expectedServerFingerprint ? (
                <span className="sv-pill is-pinned" title="Connect checks the server against its saved SHA256 fingerprint">
                  <Icon icon={BadgeCheck} />
                  Host key pinned
                </span>
              ) : (
                <span className="sv-dim" title="Any host key is accepted for this server">
                  Host key not pinned
                </span>
              )}
            </div>
          </div>

          <div className="sv-actions">
            <div className="sv-btns">
              {selected ? (
                <span className="sv-current anim-swap" ref={currentRef} tabIndex={-1}>
                  <Icon icon={Check} />
                  Used by Connect
                </span>
              ) : (
                <Button size="sm" className="sv-use anim-swap" aria-label={`Use ${name} for Connect`} onClick={onUse}>
                  Use for Connect
                </Button>
              )}
              <IconButton icon={Pencil} label={`Edit ${name}`} tooltip="Edit" onClick={() => onEdit()} />
              <IconButton icon={Trash2} label={`Delete ${name}`} tooltip="Delete" className="sv-del" onClick={onDelete} />
            </div>
            {sessionOn && !selected ? (
              <span className="sv-next">
                <Icon icon={Clock} />
                Applies on next connect
              </span>
            ) : null}
          </div>
        </article>
      </div>
    </div>
  );
}
