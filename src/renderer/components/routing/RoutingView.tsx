import { Download, Plus, RefreshCw, Search, Trash2, Upload } from "lucide-react";
import type { ChangeEvent, Dispatch, SetStateAction } from "react";
import { placeholderForRule, routingSaveLabel } from "../../lib/labels.js";
import type { RoutingSaveState } from "../../types.js";
import type { RoutingRule, RoutingRuleType } from "../../../shared/types.js";
import { EmptyState, Segmented } from "../ui/index.js";

export function RoutingView({
  ruleTab,
  ruleSearch,
  ruleValue,
  ruleError,
  routingSaveState,
  filteredRules,
  filteredProcesses,
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
  onUpdateRules
}: {
  ruleTab: RoutingRuleType;
  ruleSearch: string;
  ruleValue: string;
  ruleError: string;
  routingSaveState: RoutingSaveState;
  filteredRules: RoutingRule[];
  filteredProcesses: string[];
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
  onUpdateRules: (mutator: (rules: RoutingRule[]) => RoutingRule[]) => void;
}): JSX.Element {
  return (
    <section className="screen">
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
