import { Copy, FileText, Github, KeyRound, Network, PanelLeftClose, PanelLeftOpen, Power, Server, Settings as SettingsIcon } from "lucide-react";
import { memo } from "react";
import type { View } from "../../types.js";
import { NavButton } from "../ui/index.js";

export const Sidebar = memo(function Sidebar({
  view,
  platform,
  arch,
  collapsed,
  loggingEnabled,
  onCopyGithub,
  onOpenGithub,
  onToggleCollapsed,
  onViewChange
}: {
  view: View;
  platform: string | undefined;
  arch: string | undefined;
  collapsed: boolean;
  loggingEnabled: boolean;
  onCopyGithub: () => void;
  onOpenGithub: () => void;
  onToggleCollapsed: () => void;
  onViewChange: (view: View) => void;
}): JSX.Element {
  return (
    <aside className={collapsed ? "sidebar collapsed" : "sidebar"} aria-label="Application navigation">
      <div className="sidebar-header">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <img src="./icon.svg" alt="" />
          </div>
          <div className="brand-copy">
            <strong>Shadow SSH</strong>
            <span className="brand-meta">{platform}/{arch}</span>
          </div>
        </div>
        <button
          type="button"
          className="icon-button sidebar-toggle"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={onToggleCollapsed}
        >
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
      </div>
      <nav>
        <div className="nav-group">
          <span className="nav-label">Workspace</span>
          <NavButton compact={collapsed} active={view === "main"} icon={<Power size={18} />} label="Main" onClick={() => onViewChange("main")} />
          <NavButton
            compact={collapsed}
            active={view === "configs"}
            icon={<Server size={18} />}
            label="SSH configs"
            onClick={() => onViewChange("configs")}
          />
          <NavButton compact={collapsed} active={view === "keys"} icon={<KeyRound size={18} />} label="SSH keys" onClick={() => onViewChange("keys")} />
          <NavButton compact={collapsed} active={view === "routing"} icon={<Network size={18} />} label="Routing" onClick={() => onViewChange("routing")} />
        </div>
        <div className="nav-group">
          <span className="nav-label">System</span>
          {loggingEnabled && (
            <NavButton compact={collapsed} active={view === "logs"} icon={<FileText size={18} />} label="Logs" onClick={() => onViewChange("logs")} />
          )}
          <NavButton
            compact={collapsed}
            active={view === "settings"}
            icon={<SettingsIcon size={18} />}
            label="Settings"
            onClick={() => onViewChange("settings")}
          />
        </div>
      </nav>
      <div className="sidebar-footer">
        <button type="button" className="github-link" aria-label="Open GitHub repository" title="Open GitHub repository" onClick={onOpenGithub}>
          <Github size={18} />
          <span>Github</span>
        </button>
        <button type="button" className="icon-button github-copy" aria-label="Copy GitHub repository link" title="Copy GitHub link" onClick={onCopyGithub}>
          <Copy size={16} />
        </button>
      </div>
    </aside>
  );
});
