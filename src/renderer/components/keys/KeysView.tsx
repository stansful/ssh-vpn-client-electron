import { Plus, SlidersHorizontal, Trash2 } from "lucide-react";
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
          <h2>Private keys</h2>
          <button type="button" className="primary-button" onClick={onNew}>
            <Plus size={16} /> New
          </button>
        </div>
        <div className="item-list">
          {keys.map((key) => (
            <article className="item" key={key.id}>
              <div>
                <strong>{key.name}</strong>
                <span>{key.fingerprint}</span>
              </div>
              <div className="item-actions">
                <button type="button" className="icon-button" onClick={() => onEdit(key)} aria-label="Edit key"><SlidersHorizontal size={16} /></button>
                <button type="button" className="icon-button danger" onClick={() => onDelete(key)} aria-label="Delete key">
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
