import { KeyRound, Plus, SlidersHorizontal, Trash2 } from "lucide-react";
import type { SshKeyMetadata } from "../../../shared/types.js";
import { EmptyState } from "../ui/index.js";

export function KeysView({
  keys,
  onNew,
  onEdit,
  onDelete
}: {
  keys: SshKeyMetadata[];
  onNew: () => void;
  onEdit: (key: SshKeyMetadata) => void;
  onDelete: (key: SshKeyMetadata) => void;
}): JSX.Element {
  return (
    <section className="screen">
      <section className="panel list-panel">
        <div className="section-title">
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><KeyRound size={18} /></span>
            <div className="panel-heading-copy">
              <h2>Private keys</h2>
              <p>Encrypted credentials available to SSH profiles</p>
            </div>
          </div>
          <div className="item-actions">
            <span className="count-badge">{keys.length} total</span>
            <button type="button" className="primary-button" onClick={onNew}>
              <Plus size={16} /> New
            </button>
          </div>
        </div>
        <div className="item-list">
          {keys.map((key) => (
            <article className="item" key={key.id}>
              <div className="item-leading">
                <span className="item-icon" aria-hidden="true"><KeyRound size={17} /></span>
                <div className="item-copy">
                  <strong>{key.name}</strong>
                  <span>{key.fingerprint}</span>
                </div>
              </div>
              <div className="item-actions">
                <button type="button" className="icon-button" onClick={() => onEdit(key)} aria-label={`Edit key ${key.name}`}><SlidersHorizontal size={16} /></button>
                <button type="button" className="icon-button danger" onClick={() => onDelete(key)} aria-label={`Delete key ${key.name}`}>
                  <Trash2 size={16} />
                </button>
              </div>
            </article>
          ))}
          {keys.length === 0 && (
            <EmptyState
              text="No private keys yet."
              action={<button type="button" className="primary-button" onClick={onNew}><Plus size={16} /> Add key</button>}
            />
          )}
        </div>
      </section>
    </section>
  );
}
