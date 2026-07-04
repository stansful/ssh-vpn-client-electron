import { Copy, Download, ExternalLink, FileText, Plus, RefreshCw, Route, Search, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useMemo, useState, type ChangeEvent, type Dispatch, type SetStateAction } from "react";
import { placeholderForRule, routingSaveLabel } from "../../lib/labels.js";
import type { RoutingSaveState } from "../../types.js";
import type { RoutingDirectList, RoutingProxyList, RoutingRule, RoutingRuleType } from "../../../shared/types.js";
import { EmptyState, Modal, Segmented } from "../ui/index.js";

export function RoutingView({
  ruleTab,
  ruleSearch,
  ruleValue,
  ruleError,
  routingSaveState,
  filteredRules,
  filteredProcesses,
  proxyList,
  directList,
  processSearch,
  enabledCount,
  onRuleTabChange,
  onRuleSearchChange,
  onRuleValueChange,
  onAddRule,
  onExportRules,
  onImportRules,
  onProcessSearchChange,
  onLoadProcesses,
  onProxyListEnabledChange,
  onRefreshProxyList,
  onDirectListEnabledChange,
  onRefreshDirectList,
  onOpenSource,
  onCopySource,
  onUpdateRules
}: {
  ruleTab: RoutingRuleType;
  ruleSearch: string;
  ruleValue: string;
  ruleError: string;
  routingSaveState: RoutingSaveState;
  filteredRules: RoutingRule[];
  filteredProcesses: string[];
  proxyList: RoutingProxyList;
  directList: RoutingDirectList;
  processSearch: string;
  enabledCount: number;
  onRuleTabChange: Dispatch<SetStateAction<RoutingRuleType>>;
  onRuleSearchChange: Dispatch<SetStateAction<string>>;
  onRuleValueChange: Dispatch<SetStateAction<string>>;
  onAddRule: () => void;
  onExportRules: () => void;
  onImportRules: (event: ChangeEvent<HTMLInputElement>) => void;
  onProcessSearchChange: Dispatch<SetStateAction<string>>;
  onLoadProcesses: () => void;
  onProxyListEnabledChange: (enabled: boolean) => void;
  onRefreshProxyList: () => void;
  onDirectListEnabledChange: (enabled: boolean) => void;
  onRefreshDirectList: () => void;
  onOpenSource: () => void;
  onCopySource: () => void;
  onUpdateRules: (mutator: (rules: RoutingRule[]) => RoutingRule[]) => void;
}): JSX.Element {
  const [openList, setOpenList] = useState<{ title: string; domains: string[] } | undefined>();
  const openListText = useMemo(() => openList?.domains.join("\n") ?? "", [openList]);
  const enabledDomainCount = (proxyList.enabled ? proxyList.domains.length : 0) + (directList.enabled ? directList.domains.length : 0);

  return (
    <section className="screen">
      <section className="panel routing-panel">
        <div className="section-title">
          <h2>Domain lists</h2>
          <span>{enabledDomainCount > 0 ? `${enabledDomainCount} active` : "Disabled"}</span>
        </div>
        <div className="routing-list-grid">
          <article className="routing-list-card">
            <div className="routing-list-main">
              <button
                type="button"
                className="routing-list-title"
                onClick={() => setOpenList({ title: "Russia inside-raw.lst", domains: proxyList.domains })}
              >
                <ShieldCheck size={16} /> Russia inside-raw.lst
              </button>
              <span>{proxyList.domains.length} proxy domains</span>
            </div>
            <label className="switch-row inline-switch compact-switch">
              <input
                type="checkbox"
                checked={proxyList.enabled}
                onChange={(event) => onProxyListEnabledChange(event.target.checked)}
              />
              <span>Use</span>
            </label>
            <button type="button" className="ghost-button" onClick={onRefreshProxyList}><RefreshCw size={16} /> Refresh</button>
          </article>

          <article className="routing-list-card">
            <div className="routing-list-main">
              <button
                type="button"
                className="routing-list-title"
                onClick={() => setOpenList({ title: "Russia outside-raw.lst", domains: directList.domains })}
              >
                <Route size={16} /> Russia outside-raw.lst
              </button>
              <span>{directList.domains.length} direct domains</span>
            </div>
            <label className="switch-row inline-switch compact-switch">
              <input
                type="checkbox"
                checked={directList.enabled}
                onChange={(event) => onDirectListEnabledChange(event.target.checked)}
              />
              <span>Use</span>
            </label>
            <button type="button" className="ghost-button" onClick={onRefreshDirectList}><RefreshCw size={16} /> Refresh</button>
          </article>
        </div>
        <div className="routing-source-row">
          <button type="button" className="routing-source-link" onClick={onOpenSource} aria-label="Open routing source">
            <ExternalLink size={16} />
            <span>Source</span>
            <strong>itdoginfo/allow-domains Russia</strong>
          </button>
          <button type="button" className="icon-button" onClick={onCopySource} aria-label="Copy routing source link" title="Copy source link">
            <Copy size={16} />
          </button>
        </div>
      </section>

      <Modal open={Boolean(openList)} title={openList?.title ?? "Routing list"} onClose={() => setOpenList(undefined)}>
        <div className="routing-list-viewer">
          <div className="routing-list-viewer-meta">
            <FileText size={16} />
            <span>{openList?.domains.length ?? 0} domains</span>
          </div>
          <textarea
            className="routing-list-textarea"
            readOnly
            value={openListText || "List is empty. Refresh it before viewing domains."}
          />
        </div>
      </Modal>

      <section className="panel routing-panel">
        <div className="section-title">
          <h2>Routing rules</h2>
          <span>{enabledCount} enabled</span>
        </div>
        <div className="toolbar">
          <Segmented<RoutingRuleType>
            value={ruleTab}
            options={[
              ["domain", "Domains"],
              ["ip", "IPs"],
              ["process.name", "Processes"]
            ]}
            onChange={onRuleTabChange}
          />
          <div className="search-box">
            <Search size={16} />
            <input value={ruleSearch} onChange={(event) => onRuleSearchChange(event.target.value)} placeholder="Search rules" />
          </div>
          <button type="button" className="ghost-button" onClick={onExportRules}><Download size={16} /> Export</button>
          <label className="ghost-button file-button">
            <Upload size={16} /> Import
            <input type="file" accept="application/json" onChange={onImportRules} />
          </label>
          <span className={`autosave-state ${routingSaveState}`}>{routingSaveLabel(routingSaveState)}</span>
        </div>

        <div className="add-rule">
          <input value={ruleValue} onChange={(event) => onRuleValueChange(event.target.value)} placeholder={placeholderForRule(ruleTab)} />
          <button type="button" className="primary-button" onClick={onAddRule}><Plus size={16} /> Add</button>
        </div>
        {ruleError && <div className="inline-error">{ruleError}</div>}

        {ruleTab === "process.name" && (
          <div className="process-picker">
            <div className="toolbar compact">
              <div className="search-box">
                <Search size={16} />
                <input value={processSearch} onChange={(event) => onProcessSearchChange(event.target.value)} placeholder="Search active processes" />
              </div>
              <button type="button" className="ghost-button" onClick={onLoadProcesses}><RefreshCw size={16} /> Refresh</button>
            </div>
            <div className="process-list">
              {filteredProcesses.slice(0, 80).map((name) => (
                <button key={name} type="button" onClick={() => onRuleValueChange(name)}>{name}</button>
              ))}
            </div>
          </div>
        )}

        <div className="rules-list">
          {filteredRules.map((rule) => (
            <article className="rule-row" key={rule.id}>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={(event) =>
                    onUpdateRules((rules) =>
                      rules.map((candidate) =>
                        candidate.id === rule.id
                          ? { ...candidate, enabled: event.target.checked, updatedAt: new Date().toISOString() }
                          : candidate
                      )
                    )
                  }
                />
                <span>{rule.enabled ? "Enabled" : "Disabled"}</span>
              </label>
              <strong>{rule.value}</strong>
              <button
                type="button"
                className="icon-button danger"
                onClick={() => onUpdateRules((rules) => rules.filter((candidate) => candidate.id !== rule.id))}
                aria-label="Delete rule"
              >
                <Trash2 size={16} />
              </button>
            </article>
          ))}
          {filteredRules.length === 0 && <EmptyState text="No rules match this view." />}
        </div>
      </section>
    </section>
  );
}
