import { FileText, KeyRound, Network, Power, Server, Settings as SettingsIcon } from "lucide-react";
import type { View } from "../../types.js";
import { NavButton } from "../ui/index.js";

export function Sidebar({
  view,
  platform,
  arch,
  loggingEnabled,
  onViewChange
}: {
  view: View;
  platform: string | undefined;
  arch: string | undefined;
  loggingEnabled: boolean;
  onViewChange: (view: View) => void;
}): JSX.Element {
  return (
    <aside className="sidebar">
      <div className="brand">
        <img src="./icon.svg" alt="" />
        <div>
          <strong>Shadow SSH</strong>
          <span>{platform}/{arch}</span>
        </div>
      </div>
      <nav>
        <NavButton active={view === "main"} icon={<Power size={18} />} label="Main" onClick={() => onViewChange("main")} />
        <NavButton active={view === "configs"} icon={<Server size={18} />} label="SSH configs" onClick={() => onViewChange("configs")} />
        <NavButton active={view === "keys"} icon={<KeyRound size={18} />} label="SSH keys" onClick={() => onViewChange("keys")} />
        <NavButton active={view === "routing"} icon={<Network size={18} />} label="Routing" onClick={() => onViewChange("routing")} />
        {loggingEnabled && <NavButton active={view === "logs"} icon={<FileText size={18} />} label="Logs" onClick={() => onViewChange("logs")} />}
        <NavButton active={view === "settings"} icon={<SettingsIcon size={18} />} label="Settings" onClick={() => onViewChange("settings")} />
      </nav>
    </aside>
  );
}
