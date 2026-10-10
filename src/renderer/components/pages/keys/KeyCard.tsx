import { Info, KeyRound, Lock, Pencil, Server, Trash2, TriangleAlert } from "lucide-react";
import { useId, type CSSProperties } from "react";
import { Badge, Button, Chip, Icon, Tooltip } from "../../ui/index.js";
import { keyLockText, keySupportIssue, keyTypeLabel, shortKeyId } from "./key-model.js";
import type { SshConfig, SshKeyMetadata } from "../../../../shared/types.js";

export interface KeyCardProps {
  sshKey: SshKeyMetadata;
  users: readonly SshConfig[];
  index: number;
  leaving: boolean;
  /** Bumps each time Delete is pressed on a key in use, to replay the nudge. */
  nudge: number;
  onEdit: () => void;
  onDelete: () => void;
  onOpenServers: () => void;
}

export function KeyCard({ sshKey, users, index, leaving, nudge, onEdit, onDelete, onOpenServers }: KeyCardProps): JSX.Element {
  const ids = useId();
  const nameId = `${ids}-name`;
  const lockId = `${ids}-lock`;
  const locked = users.length > 0;
  const issue = keySupportIssue(sshKey);
  const name = sshKey.name || "Unnamed key";

  return (
    <div className="ky-slot" role="listitem" data-leaving={leaving ? "true" : "false"} aria-hidden={leaving || undefined}>
      <div className="ky-rise rise" style={{ "--d": Math.min(index + 2, 12) } as CSSProperties}>
        <article className="ky-card" aria-labelledby={nameId}>
          <div className="ky-top">
            <span className="icon-tile ky-tile" data-used={locked ? "true" : "false"} aria-hidden="true">
              <Icon icon={KeyRound} />
            </span>
            <div className="ky-tags">
              {issue ? (
                <Badge tone="warn" icon={TriangleAlert} title={issue}>
                  Can’t sign in yet
                </Badge>
              ) : null}
              <Badge tone="outline" square title="Key type">
                {keyTypeLabel(sshKey.keyType)}
              </Badge>
            </div>
          </div>

          <div className="ky-ident">
            <h3 className="ky-name" id={nameId}>
              {name}
            </h3>
            <div className="ky-kid">
              <span className="ky-kid-label">Key ID</span>
              <span className="mono truncate" title={sshKey.fingerprint}>
                {shortKeyId(sshKey.fingerprint)}
              </span>
              <Tooltip
                align="end"
                className="ky-tip"
                content="Shadow’s own ID for the saved key text — not the OpenSSH fingerprint. It changes only when you replace the key."
              >
                <button type="button" className="help-tip-btn" aria-label="What is the Key ID?">
                  <Icon icon={Info} />
                </button>
              </Tooltip>
            </div>
          </div>

          <dl className="ky-facts">
            <div className="ky-fact">
              <dt>Passphrase</dt>
              <dd>
                {sshKey.privateKeyPassphraseSecretId ? (
                  <Badge tone="ok" icon={Lock}>
                    Passphrase saved
                  </Badge>
                ) : (
                  <Badge tone="outline">No passphrase</Badge>
                )}
              </dd>
            </div>
            <div className="ky-fact">
              <dt>Used by</dt>
              <dd>
                {users.map((config) => (
                  <Chip key={config.id} ui icon={Server} className="ky-use" ariaLabel={`Used by ${config.name}. Open SSH servers`} title="Open SSH servers" onClick={onOpenServers}>
                    {config.name}
                  </Chip>
                ))}
                {!locked ? <span className="ky-unused">Not used by any server</span> : null}
              </dd>
            </div>
          </dl>

          {locked ? (
            <p className="ky-lock" id={lockId} data-nudge={nudge > 0 ? "true" : "false"} key={`lock-${nudge}`}>
              <Icon icon={Lock} />
              {keyLockText(users.map((config) => config.name))}
            </p>
          ) : null}

          <div className="ky-foot">
            <Button size="sm" icon={Pencil} aria-label={`Edit ${name}`} onClick={onEdit}>
              Edit
            </Button>
            <Button
              size="sm"
              variant="ghost"
              icon={Trash2}
              className="ky-del"
              aria-disabled={locked || undefined}
              aria-label={locked ? `Delete ${name}, unavailable while a server uses it` : `Delete ${name}`}
              aria-describedby={locked ? lockId : undefined}
              onClick={onDelete}
            >
              Delete
            </Button>
          </div>
        </article>
      </div>
    </div>
  );
}
