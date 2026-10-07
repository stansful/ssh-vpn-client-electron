import { KeyRound, Pencil } from "lucide-react";
import { useRef, useState } from "react";
import { initials } from "../../../lib/format.js";
import { Badge, Button, IconButton, Modal } from "../../ui/index.js";
import { serverAddress } from "../servers/server-model.js";
import { keyInUseDescription } from "./key-model.js";
import type { SshConfig, SshKeyMetadata } from "../../../../shared/types.js";

export interface KeyInUse {
  key: SshKeyMetadata;
  users: SshConfig[];
}

export interface KeyInUseDialogProps {
  value: KeyInUse | null;
  onClose: () => void;
  onEditServer: (configId: string) => void;
}

/** "Can't delete … yet": names the servers that still sign in with the key, before anything fails. */
export function KeyInUseDialog({ value, onClose, onEditServer }: KeyInUseDialogProps): JSX.Element | null {
  const closeRef = useRef<HTMLButtonElement>(null);
  const [last, setLast] = useState<KeyInUse | null>(value);
  if (value && value !== last) {
    setLast(value);
  }
  const shown = value ?? last;
  if (!shown) {
    return null;
  }
  const single = shown.users.length === 1 ? shown.users[0] : undefined;

  return (
    <Modal
      open={value !== null}
      onClose={onClose}
      role="alertdialog"
      size="confirm"
      closeButton={false}
      eyebrow="SSH keys"
      icon={KeyRound}
      iconTone="warn"
      title={`Can't delete ${shown.key.name} yet`}
      description={keyInUseDescription(shown.users.length)}
      initialFocusRef={closeRef}
      footer={
        <>
          <Button ref={closeRef} onClick={onClose}>
            Close
          </Button>
          {single ? (
            <Button variant="primary" icon={Pencil} onClick={() => onEditServer(single.id)}>
              Edit {single.name}
            </Button>
          ) : null}
        </>
      }
    >
      <div className="ky-users">
        {shown.users.map((config) => (
          <div className="item" key={config.id}>
            <span className="avatar" aria-hidden="true">
              {initials(config.name)}
            </span>
            <div className="item-main">
              <span className="item-title">{config.name}</span>
              <span className="item-sub">
                <span className="mono">{serverAddress(config)}</span>
              </span>
            </div>
            {single ? (
              <Badge tone="outline" icon={KeyRound}>
                {shown.key.name}
              </Badge>
            ) : (
              <IconButton icon={Pencil} label={`Edit ${config.name}`} tooltip="Edit" onClick={() => onEditServer(config.id)} />
            )}
          </div>
        ))}
      </div>
    </Modal>
  );
}
