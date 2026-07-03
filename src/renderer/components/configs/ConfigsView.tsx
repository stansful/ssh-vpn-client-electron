import { Plus, SlidersHorizontal, Trash2 } from "lucide-react";
import type { SshConfig } from "../../../shared/types.js";
import { EmptyState } from "../ui/index.js";

export function ConfigsView({
  configs,
  onNew,
  onSelect,
  onEdit,
  onDelete
}: {
  configs: SshConfig[];
  onNew: () => void;
  onSelect: (id: string) => void;
  onEdit: (config: SshConfig) => void;
  onDelete: (config: SshConfig) => void;
}): JSX.Element {
  return (
    <section className="screen">
      <section className="panel list-panel">
        <div className="section-title">
          <h2>Saved configurations</h2>
          <button type="button" className="primary-button" onClick={onNew}>
            <Plus size={16} /> New
          </button>
        </div>
        <div className="item-list">
          {configs.map((config) => (
            <article className="item" key={config.id}>
              <div>
                <strong>{config.name}</strong>
                <span>{config.username}@{config.host}:{config.port}</span>
              </div>
              <div className="item-actions">
                <button type="button" className="ghost-button" onClick={() => onSelect(config.id)}>Select</button>
                <button type="button" className="icon-button" onClick={() => onEdit(config)} aria-label="Edit configuration"><SlidersHorizontal size={16} /></button>
                <button type="button" className="icon-button danger" onClick={() => onDelete(config)} aria-label="Delete configuration">
                  <Trash2 size={16} />
                </button>
              </div>
            </article>
          ))}
          {configs.length === 0 && (
            <EmptyState
              text="No SSH configurations yet."
              action={<button type="button" className="primary-button" onClick={onNew}><Plus size={16} /> Add config</button>}
            />
          )}
        </div>
      </section>
    </section>
  );
}
