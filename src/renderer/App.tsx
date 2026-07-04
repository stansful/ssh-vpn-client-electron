import { useEffect, useState } from "react";
import { api } from "./api.js";
import { AppModals } from "./components/app/AppModals.js";
import { AppViews } from "./components/app/AppViews.js";
import { Notice } from "./components/layout/Notice.js";
import { Sidebar } from "./components/layout/Sidebar.js";
import { Topbar } from "./components/layout/Topbar.js";
import { useAsyncAction } from "./hooks/useAsyncAction.js";
import { useEndpointController } from "./hooks/useEndpointController.js";
import { useLogsController } from "./hooks/useLogsController.js";
import { useRoutingController } from "./hooks/useRoutingController.js";
import { useSnapshot } from "./hooks/useSnapshot.js";
import { useSshEntitiesController } from "./hooks/useSshEntitiesController.js";
import { useTerminalController } from "./hooks/useTerminalController.js";
import { useUpdateController } from "./hooks/useUpdateController.js";
import { useXrayController } from "./hooks/useXrayController.js";
import { titleForView } from "./lib/labels.js";
import { createThemeVars, resolveTheme } from "./lib/theme.js";
import type { View } from "./types.js";
import { createDefaultStore } from "../shared/defaults.js";
import { GITHUB_REPOSITORY_URL } from "../shared/links.js";
import type { AppSettings } from "../shared/types.js";

export function App(): JSX.Element {
  const [view, setView] = useState<View>("main");
  const [checking, setChecking] = useState(false);
  const { snapshot, setSnapshot, notice, setNotice } = useSnapshot();
  const { busy, setBusy, run, commitSnapshotAction } = useAsyncAction({ setSnapshot, setNotice });

  const store = snapshot?.store ?? createDefaultStore();
  const runtime = snapshot?.runtime;
  const selectedConfig = store.sshConfigs.find((config) => config.id === store.selectedConfigId);
  const enabledRules = store.routingRules.filter((rule) => rule.enabled);
  const selectedRulesBlocked =
    store.routingMode === "selected-rules" &&
    enabledRules.length === 0 &&
    (!store.routingProxyList.enabled || store.routingProxyList.domains.length === 0);
  const loggingEnabled = store.settings.loggingEnabled;
  const sidebarCollapsed = store.settings.sidebarCollapsed;
  const theme = resolveTheme(store.settings.theme);
  const customStyle = createThemeVars(store.settings);

  function updateSettings(patch: Partial<AppSettings>): void {
    void run(() => api.updateSettings({ ...store.settings, ...patch }));
  }

  const routing = useRoutingController({ snapshot, setSnapshot, setNotice, run });
  const ssh = useSshEntitiesController({ setSnapshot, setBusy, setView });
  const endpoint = useEndpointController({ settings: store.settings, setSnapshot, setBusy });
  const terminal = useTerminalController({ snapshot, runtime, setSnapshot, setNotice });
  const logs = useLogsController({ view, snapshot, setSnapshot, setNotice });
  const xray = useXrayController({
    setSnapshot,
    setNotice,
    updateSettings,
    commitSnapshotAction,
    setBusy
  });
  const updates = useUpdateController({ run, setNotice });

  function openGithubRepository(): void {
    void run(async () => {
      await api.openExternal(GITHUB_REPOSITORY_URL);
    });
  }

  function copyGithubRepositoryLink(): void {
    void run(async () => {
      const copied = await api.copyText(GITHUB_REPOSITORY_URL);
      if (!copied) {
        throw new Error("Unable to copy GitHub link.");
      }
      setNotice("GitHub link copied.");
    });
  }

  useEffect(() => {
    if (!loggingEnabled && view === "logs") {
      setView("main");
    }
  }, [loggingEnabled, view]);

  if (!snapshot) {
    return (
      <div className="app-shell" data-theme={theme} style={customStyle}>
        <main className="loading">Loading Shadow SSH...</main>
      </div>
    );
  }

  return (
    <div className={sidebarCollapsed ? "app-shell sidebar-collapsed" : "app-shell"} data-theme={theme} style={customStyle}>
      <Sidebar
        view={view}
        platform={runtime?.platformTarget.platform}
        arch={runtime?.platformTarget.arch}
        collapsed={sidebarCollapsed}
        loggingEnabled={loggingEnabled}
        onCopyGithub={copyGithubRepositoryLink}
        onOpenGithub={openGithubRepository}
        onToggleCollapsed={() => updateSettings({ sidebarCollapsed: !sidebarCollapsed })}
        onViewChange={setView}
      />

      <main className="content">
        <Topbar title={titleForView(view)} message={runtime?.message} state={runtime?.state ?? "Disconnected"} />
        <Notice message={notice} onDismiss={() => setNotice("")} />
        <AppViews
          view={view}
          snapshot={snapshot}
          runtime={runtime}
          selectedConfig={selectedConfig}
          selectedRulesBlocked={selectedRulesBlocked}
          busy={busy}
          checking={checking}
          setChecking={setChecking}
          run={run}
          commitSnapshotAction={commitSnapshotAction}
          updateSettings={updateSettings}
          openEndpointModal={endpoint.openEndpointModal}
          routing={routing}
          ssh={ssh}
          terminal={terminal}
          logs={logs}
          xray={xray}
          updates={updates}
        />
      </main>

      <AppModals store={store} ssh={ssh} endpoint={endpoint} />
    </div>
  );
}
