import { Plus, Server, SlidersHorizontal, Trash2 } from "lucide-react";
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
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><Server size={18} /></span>
            <div className="panel-heading-copy">
              <h2>Saved configurations</h2>
              <p>Secure connection profiles stored on this device</p>
            </div>
          </div>
          <div className="item-actions">
            <span className="count-badge">{configs.length} total</span>
            <button type="button" className="primary-button" onClick={onNew}>
              <Plus size={16} /> New
            </button>
          </div>
        </div>
        <div className="item-list">
          {configs.map((config) => (
            <article className="item" key={config.id}>
              <div className="item-leading">
                <span className="item-icon" aria-hidden="true"><Server size={17} /></span>
                <div className="item-copy">
                  <strong>{config.name}</strong>
                  <span>{config.username}@{config.host}:{config.port}</span>
                </div>
              </div>
              <div className="item-actions">
                <button type="button" className="ghost-button" aria-label={`Select configuration ${config.name}`} onClick={() => onSelect(config.id)}>Select</button>
                <button type="button" className="icon-button" onClick={() => onEdit(config)} aria-label={`Edit configuration ${config.name}`}><SlidersHorizontal size={16} /></button>
                <button type="button" className="icon-button danger" onClick={() => onDelete(config)} aria-label={`Delete configuration ${config.name}`}>
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
