import {
  Activity,
  KeyRound,
  LoaderCircle,
  PanelLeft,
  Power,
  Route,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
  Zap,
  type LucideIcon
} from "lucide-react";
import { useEffect, useState } from "react";
import { hysteria2CheckState, presentGlobalStatus, toneClass, type GlobalStatusPresentation } from "../../lib/connection.js";
import { formatCount } from "../../lib/format.js";
import { useAppData } from "../../hooks/useAppData.js";
import { useNavigation } from "../../hooks/useNavigation.js";
import type { View } from "../../types.js";
import { IconButton } from "../ui/Button.js";
import { Icon } from "../ui/Icon.js";
import { activeProfileProtocol, activeTargetName } from "./connection-target.js";

interface NavEntry {
  view: View;
  label: string;
  icon: LucideIcon;
  count?: number;
}

const STATUS_ICON: Record<GlobalStatusPresentation["icon"], LucideIcon> = {
  off: Power,
  busy: LoaderCircle,
  ok: ShieldCheck,
  danger: TriangleAlert,
  warn: ShieldAlert
};

/**
 * App navigation: Tunnel / Library / App groups with counts, a collapse
 * toggle (persisted in settings), and the global status card for the ACTIVE
 * transport at the bottom. Under 860 px it becomes a top strip (CSS).
 */
export function Sidebar(): JSX.Element {
  const { snapshot, store, runtime, activeTransport, environment, updateSettings } = useAppData();
  const { view, navigate } = useNavigation();
  const savedCollapsed = store.settings.sidebarCollapsed;
  const [collapsed, setCollapsed] = useState(savedCollapsed);

  // Follow changes saved elsewhere (another window, a reload).
  useEffect(() => setCollapsed(savedCollapsed), [savedCollapsed]);

  const status = presentGlobalStatus({
    runtime,
    activeTransport,
    platform: environment.platform,
    targetName: activeTargetName(snapshot),
    hysteria2Check: hysteria2CheckState({
      runtime,
      activeTransport,
      protocol: activeProfileProtocol(snapshot),
      lastTunnelCheck: snapshot.lastTunnelCheck
    })
  });
  const statusTone = status.tone === "neutral" ? "none" : status.tone;
  const groups: Array<{ label: string; items: NavEntry[] }> = [
    {
      label: "Tunnel",
      items: [
        { view: "connect", label: "Connect", icon: Power },
        { view: "routing", label: "Routing", icon: Route, count: store.routingRules.length }
      ]
    },
    {
      label: "Library",
      items: [
        { view: "servers", label: "SSH servers", icon: Server, count: store.sshConfigs.length },
        { view: "profiles", label: "Xray profiles", icon: Zap, count: store.proxyProfiles.length },
        { view: "keys", label: "SSH keys", icon: KeyRound, count: store.sshKeys.length }
      ]
    },
    {
      label: "App",
      items: [
        ...(store.settings.loggingEnabled ? [{ view: "activity" as const, label: "Activity", icon: Activity }] : []),
        { view: "settings", label: "Settings", icon: SlidersHorizontal }
      ]
    }
  ];
  const toggleLabel = collapsed ? "Expand sidebar" : "Collapse sidebar";
  const meta = `${environment.platform} · ${environment.arch} · ${environment.version}`;
  const StatusIcon = STATUS_ICON[status.icon];

  return (
    <aside className="sb" data-collapsed={collapsed ? "true" : "false"} aria-label="Shadow SSH">
      <div className="sb-head">
        <button
          type="button"
          className="sb-mark"
          aria-label={`Shadow SSH — ${status.title}. Open Connect.`}
          title={`Shadow SSH — ${status.title}`}
          onClick={() => navigate("connect")}
        >
          <img src="./icon.svg" alt="" />
          <span className={["dot", toneClass(status.tone)].filter(Boolean).join(" ")} aria-hidden="true" />
        </button>
        <div className="sb-brand">
          <span className="sb-name">Shadow SSH</span>
          <span className="sb-meta">{meta}</span>
        </div>
        <IconButton
          icon={PanelLeft}
          label={toggleLabel}
          className="sb-toggle"
          aria-expanded={!collapsed}
          onClick={() => {
            const next = !collapsed;
            setCollapsed(next);
            void updateSettings({ sidebarCollapsed: next });
          }}
        />
      </div>

      <nav className="nav" aria-label="Application navigation">
        {groups.map((group) => (
          <div className="nav-group" key={group.label}>
            <span className="nav-label" aria-hidden="true">
              {group.label}
            </span>
            {group.items.map((item) => (
              <button
                key={item.view}
                type="button"
                className="nav-item"
                aria-current={view === item.view ? "page" : undefined}
                aria-label={item.count !== undefined ? `${item.label}, ${item.count}` : item.label}
                title={item.label}
                onClick={() => navigate(item.view)}
              >
                <Icon icon={item.icon} />
                <span className="nav-text">{item.label}</span>
                {item.count !== undefined ? <span className="nav-count">{formatCount(item.count)}</span> : null}
              </button>
            ))}
          </div>
        ))}
      </nav>

      <button type="button" className="sb-status" data-tone={statusTone} aria-label={status.ariaLabel} title={`${status.title} · ${status.subtitle}`} onClick={() => navigate("connect")}>
        <span className="sb-status-icon">
          <Icon icon={StatusIcon} spin={status.icon === "busy"} />
        </span>
        <span className="sb-status-copy">
          <span className="sb-status-title">{status.title}</span>
          <span className="sb-status-sub">{status.subtitle}</span>
        </span>
      </button>
      <span className="sr-only" aria-live="polite">
        {status.title}
      </span>
    </aside>
  );
}
