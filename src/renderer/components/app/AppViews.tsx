import type { Dispatch, SetStateAction } from "react";
import { api } from "../../api.js";
import { ConfigsView } from "../configs/ConfigsView.js";
import { KeysView } from "../keys/KeysView.js";
import { LogsView } from "../logs/LogsView.js";
import { MainView } from "../main/MainView.js";
import { RoutingView } from "../routing/RoutingView.js";
import { SettingsView } from "../settings/SettingsView.js";
import { XrayView } from "../xray/XrayView.js";
import { Segmented } from "../ui/index.js";
import { emptyConfigDraft, emptyKeyDraft, type View } from "../../types.js";
import type { useLogsController } from "../../hooks/useLogsController.js";
import type { useRoutingController } from "../../hooks/useRoutingController.js";
import type { useSshEntitiesController } from "../../hooks/useSshEntitiesController.js";
import type { useTerminalController } from "../../hooks/useTerminalController.js";
import type { useUpdateController } from "../../hooks/useUpdateController.js";
import type { useXrayController } from "../../hooks/useXrayController.js";
import type { AppSettings, AppSnapshot, GlobalTab, RuntimeStatus, SshConfig } from "../../../shared/types.js";

type RunAction = (action: () => Promise<AppSnapshot | void>) => Promise<void>;

export function AppViews({
  view,
  snapshot,
  runtime,
  selectedConfig,
  selectedRulesBlocked,
  busy,
  checking,
  setChecking,
  run,
  commitSnapshotAction,
  updateSettings,
  openEndpointModal,
  routing,
  ssh,
  terminal,
  logs,
  xray,
  updates
}: {
  view: View;
  snapshot: AppSnapshot;
  runtime: RuntimeStatus | undefined;
  selectedConfig: SshConfig | undefined;
  selectedRulesBlocked: boolean;
  busy: boolean;
  checking: boolean;
  setChecking: Dispatch<SetStateAction<boolean>>;
  run: RunAction;
  commitSnapshotAction: (action: () => Promise<AppSnapshot>, successMessage?: string) => Promise<void>;
  updateSettings: (patch: Partial<AppSettings>) => void;
  openEndpointModal: () => void;
  routing: ReturnType<typeof useRoutingController>;
  ssh: ReturnType<typeof useSshEntitiesController>;
  terminal: ReturnType<typeof useTerminalController>;
  logs: ReturnType<typeof useLogsController>;
  xray: ReturnType<typeof useXrayController>;
  updates: ReturnType<typeof useUpdateController>;
}): JSX.Element | null {
  const store = snapshot.store;

  if (view === "main") {
    return (
      <section className="screen main-transport-screen">
        <div className="main-transport-switch">
          <Segmented<GlobalTab>
            value={store.settings.activeGlobalTab}
            options={[
              ["ssh", "SSH"],
              ["xray", "Xray"]
            ]}
            onChange={(activeGlobalTab) => updateSettings({ activeGlobalTab })}
          />
        </div>
        {store.settings.activeGlobalTab === "xray" ? (
          <XrayView
            snapshot={snapshot}
            busy={busy}
            checking={checking}
            selectedRulesBlocked={selectedRulesBlocked}
            onConnect={() => void run(() => api.connectProxy())}
            onDisconnect={() => void run(() => api.disconnect())}
            onCheckTunnel={() => {
              setChecking(true);
              void run(async () => api.checkTunnel(store.settings.checkEndpoint)).finally(() => setChecking(false));
            }}
            onEditEndpoint={openEndpointModal}
            onRefresh={xray.refreshProxyProfiles}
            onUpsert={xray.upsertProxyProfile}
            onImport={xray.importProxyProfiles}
            onSelect={(id) => run(() => api.selectProxyProfile(id))}
            onTogglePin={(id) => run(() => api.toggleProxyProfilePin(id))}
            onDelete={(id) => commitSnapshotAction(() => api.deleteProxyProfile(id), "Xray profile deleted.")}
            onDeleteUnpinned={() => commitSnapshotAction(() => api.deleteUnpinnedProxyProfiles(), "Unpinned Xray profiles deleted.")}
            onAcceptRisk={xray.acceptXrayRisk}
          />
        ) : (
          <MainView
            store={store}
            runtime={runtime}
            selectedConfig={selectedConfig}
            selectedRulesBlocked={selectedRulesBlocked}
            busy={busy}
            checking={checking}
            lastTunnelCheck={snapshot.lastTunnelCheck}
            terminalText={terminal.terminalText}
            terminalInput={terminal.terminalInput}
            terminalOpening={terminal.terminalOpening}
            onSelectConfig={(id) => void run(() => api.selectConfig(id))}
            onConnect={() => void run(() => api.connect())}
            onDisconnect={() => void run(() => api.disconnect())}
            onCheckTunnel={() => {
              setChecking(true);
              void run(async () => api.checkTunnel(store.settings.checkEndpoint)).finally(() => setChecking(false));
            }}
            onEditEndpoint={openEndpointModal}
            onTerminalToggle={(open) => void terminal.handleTerminalToggle(open)}
            onCloseTerminalShell={() => void terminal.closeTerminalShell()}
            onTerminalInputChange={terminal.setTerminalInput}
            onTerminalSubmit={terminal.sendTerminalInput}
          />
        )}
      </section>
    );
  }

  if (view === "configs") {
    return (
      <ConfigsView
        configs={store.sshConfigs}
        onNew={() => ssh.openConfigModal(emptyConfigDraft())}
        onSelect={(id) => void run(() => api.selectConfig(id))}
        onEdit={ssh.editConfig}
        onDelete={(config) => {
          if (window.confirm(`Delete SSH configuration "${config.name}"?`)) {
            void run(() => api.deleteConfig(config.id));
          }
        }}
      />
    );
  }

  if (view === "keys") {
    return (
      <KeysView
        keys={store.sshKeys}
        onNew={() => ssh.openKeyModal(emptyKeyDraft())}
        onEdit={ssh.editKey}
        onDelete={(key) => {
          if (window.confirm(`Delete SSH key "${key.name}"?`)) {
            void run(() => api.deleteKey(key.id));
          }
        }}
      />
    );
  }

  if (view === "routing") {
    return (
      <RoutingView
        ruleTab={routing.ruleTab}
        ruleSearch={routing.ruleSearch}
        ruleValue={routing.ruleValue}
        ruleError={routing.ruleError}
        routingSaveState={routing.routingSaveState}
        filteredRules={routing.filteredRules}
        filteredProcesses={routing.filteredProcesses}
        proxyList={store.routingProxyList}
        directList={store.routingDirectList}
        processSearch={routing.processSearch}
        enabledCount={routing.routingDraft.filter((rule) => rule.enabled).length}
        onRuleTabChange={routing.setRuleTab}
        onRuleSearchChange={routing.setRuleSearch}
        onRuleValueChange={routing.setRuleValue}
        onAddRule={routing.addRule}
        onExportRules={routing.exportRules}
        onImportRules={routing.importRules}
        onProcessSearchChange={routing.setProcessSearch}
        onLoadProcesses={routing.loadProcesses}
        onProxyListEnabledChange={routing.updateProxyListEnabled}
        onRefreshProxyList={routing.refreshProxyList}
        onDirectListEnabledChange={routing.updateDirectListEnabled}
        onRefreshDirectList={routing.refreshDirectList}
        onUpdateRules={routing.updateRoutingDraft}
      />
    );
  }

  if (view === "logs") {
    return (
      <LogsView
        snapshot={snapshot}
        fileLog={logs.fileLog}
        fileLogBusy={logs.fileLogBusy}
        onUpdateSettings={updateSettings}
        onRefresh={logs.refreshFileLog}
        onCopy={logs.copyUnifiedLog}
        onClear={logs.clearUnifiedLog}
      />
    );
  }

  if (view === "settings") {
    return (
      <SettingsView
        store={store}
        loggingEnabled={store.settings.loggingEnabled}
        updateInfo={snapshot.updateInfo}
        updateDownload={snapshot.updateDownload}
        onCheckForUpdates={updates.checkForUpdates}
        onDownloadUpdate={updates.downloadUpdate}
        onRevealDownloadedUpdate={updates.revealDownloadedUpdate}
        onRoutingModeChange={(mode) => void run(() => api.updateRoutingMode(mode))}
        onUpdateSettings={updateSettings}
        platform={runtime?.platformTarget.platform}
      />
    );
  }

  return null;
}
