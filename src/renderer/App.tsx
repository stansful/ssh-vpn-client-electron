import { LoaderCircle, RotateCcw, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api.js";
import { AppModals } from "./components/app/AppModals.js";
import { AppViews } from "./components/app/AppViews.js";
import { Notice } from "./components/layout/Notice.js";
import { Sidebar } from "./components/layout/Sidebar.js";
import { Topbar } from "./components/layout/Topbar.js";
import { ConfirmationModal } from "./components/ui/index.js";
import { useAsyncAction } from "./hooks/useAsyncAction.js";
import { useConfirmationController } from "./hooks/useConfirmationController.js";
import { useEndpointController } from "./hooks/useEndpointController.js";
import { useLogsController } from "./hooks/useLogsController.js";
import { useRoutingController } from "./hooks/useRoutingController.js";
import { useResolvedTheme } from "./hooks/useResolvedTheme.js";
import { useSnapshot } from "./hooks/useSnapshot.js";
import { useSshEntitiesController } from "./hooks/useSshEntitiesController.js";
import { useTerminalController } from "./hooks/useTerminalController.js";
import { useUpdateController } from "./hooks/useUpdateController.js";
import { useXrayController } from "./hooks/useXrayController.js";
import { titleForView } from "./lib/labels.js";
import { createThemeVars } from "./lib/theme.js";
import type { View } from "./types.js";
import { createDefaultStore } from "../shared/defaults.js";
import { GITHUB_REPOSITORY_URL } from "../shared/links.js";
import type { AppSettings } from "../shared/types.js";
import { validateRoutingRuleValue } from "../shared/validation.js";
import { normalizeProxyDomain } from "../core/routing/domain-proxy-list.js";

export function App(): JSX.Element {
  const [view, setView] = useState<View>("main");
  const previousViewRef = useRef<View>("main");
  const [checking, setChecking] = useState(false);
  const { snapshot, setSnapshot, notice, setNotice, startupError, retrySnapshot } = useSnapshot();
  const { busy, setBusy, run, commitSnapshotAction } = useAsyncAction({ setSnapshot, setNotice });
  const confirmation = useConfirmationController();

  const defaultStore = useMemo(createDefaultStore, []);
  const store = snapshot?.store ?? defaultStore;
  const runtime = snapshot?.runtime;
  const selectedConfig = useMemo(
    () => store.sshConfigs.find((config) => config.id === store.selectedConfigId),
    [store.selectedConfigId, store.sshConfigs]
  );
  const selectedRulesBlocked = useMemo(() => {
    if (store.routingMode !== "selected-rules") {
      return false;
    }
    const hasEnabledRule = store.routingRules.some(
      (rule) => rule.enabled && validateRoutingRuleValue(rule.type, rule.value).ok
    );
    const hasValidProxyListDomain = store.routingProxyList.enabled && store.routingProxyList.domains.some(
      (domain) => normalizeProxyDomain(domain) !== undefined
    );
    return !hasEnabledRule && !hasValidProxyListDomain;
  }, [store.routingMode, store.routingProxyList.domains, store.routingProxyList.enabled, store.routingRules]);
  const loggingEnabled = store.settings.loggingEnabled;
  const sidebarCollapsed = store.settings.sidebarCollapsed;
  const theme = useResolvedTheme(store.settings.theme);
  const customStyle = useMemo(() => createThemeVars(store.settings), [store.settings]);

  const updateSettings = useCallback((patch: Partial<AppSettings>): void => {
    void run(() => api.updateSettings(patch));
  }, [run]);

  const routing = useRoutingController({ snapshot, setSnapshot, setNotice, run });
  const ssh = useSshEntitiesController({ setSnapshot, setBusy, setView });
  const endpoint = useEndpointController({ settings: store.settings, setSnapshot, setBusy });
  const terminal = useTerminalController({
    snapshot,
    runtime,
    terminalVisible:
      view === "main" &&
      store.settings.activeGlobalTab === "ssh" &&
      store.settings.terminalExpanded,
    setSnapshot,
    setNotice
  });
  const logs = useLogsController({ view, snapshot, setSnapshot, setNotice });
  const xray = useXrayController({
    setSnapshot,
    setNotice,
    updateSettings,
    commitSnapshotAction,
    setBusy
  });
  const updates = useUpdateController({ run, setNotice });

  const openGithubRepository = useCallback((): void => {
    void run(async () => {
      await api.openExternal(GITHUB_REPOSITORY_URL);
    });
  }, [run]);

  const copyGithubRepositoryLink = useCallback((): void => {
    void run(async () => {
      const copied = await api.copyText(GITHUB_REPOSITORY_URL);
      if (!copied) {
        throw new Error("Unable to copy GitHub link.");
      }
      setNotice("GitHub link copied.");
    });
  }, [run, setNotice]);

  const toggleSidebar = useCallback((): void => {
    updateSettings({ sidebarCollapsed: !sidebarCollapsed });
  }, [sidebarCollapsed, updateSettings]);

  const dismissNotice = useCallback((): void => setNotice(""), [setNotice]);

  useEffect(() => {
    if (!loggingEnabled && view === "logs") {
      setView("main");
    }
  }, [loggingEnabled, view]);

  useEffect(() => {
    if (previousViewRef.current === view) {
      return undefined;
    }
    previousViewRef.current = view;
    const frame = window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>(".topbar h1")?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [view]);

  if (!snapshot) {
    return (
      <div
        className="app-shell"
        data-theme={theme}
        data-startup-state={startupError ? "error" : "loading"}
        data-connection-state="Disconnected"
        style={customStyle}
      >
        <main className="startup-screen">
          <section className="loading" aria-live="polite">
            <div className="startup-brand">
              <div className="brand-mark" aria-hidden="true"><img src="./icon.svg" alt="" /></div>
              <div className="startup-brand-copy">
                <span>Secure network control</span>
                <strong>Shadow SSH</strong>
              </div>
            </div>
            {startupError ? (
              <>
                <strong>Shadow SSH could not load its initial state.</strong>
                <span className="startup-error" role="alert">{startupError}</span>
                <button type="button" className="primary-button" onClick={retrySnapshot}><RotateCcw size={16} /> Retry</button>
              </>
            ) : (
              <div className="startup-loading-row">
                <LoaderCircle className="spin" size={18} aria-hidden="true" />
                <span>Preparing your secure workspace…</span>
                <ShieldCheck size={17} aria-hidden="true" />
              </div>
            )}
          </section>
        </main>
      </div>
    );
  }

  return (
    <div
      className={sidebarCollapsed ? "app-shell sidebar-collapsed" : "app-shell"}
      data-theme={theme}
      data-startup-state="ready"
      data-connection-state={runtime?.state ?? "Disconnected"}
      style={customStyle}
    >
      <Sidebar
        view={view}
        platform={runtime?.platformTarget.platform}
        arch={runtime?.platformTarget.arch}
        collapsed={sidebarCollapsed}
        loggingEnabled={loggingEnabled}
        onCopyGithub={copyGithubRepositoryLink}
        onOpenGithub={openGithubRepository}
        onToggleCollapsed={toggleSidebar}
        onViewChange={setView}
      />

      <main className="content" tabIndex={-1}>
        <Topbar title={titleForView(view)} message={runtime?.message} state={runtime?.state ?? "Disconnected"} />
        <Notice message={notice} onDismiss={dismissNotice} />
        <AppViews
          view={view}
          onViewChange={setView}
          snapshot={snapshot}
          runtime={runtime}
          selectedConfig={selectedConfig}
          selectedRulesBlocked={selectedRulesBlocked}
          busy={busy}
          checking={checking}
          setChecking={setChecking}
          run={run}
          commitSnapshotAction={commitSnapshotAction}
          requestConfirmation={confirmation.request}
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
      <ConfirmationModal
        state={confirmation.state}
        onCancel={confirmation.cancel}
        onConfirm={confirmation.confirm}
      />
    </div>
  );
}
