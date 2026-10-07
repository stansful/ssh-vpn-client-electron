import { AppWindow, Download, Globe, List, Network, Plus, Search, Trash2, TriangleAlert, Upload, type LucideIcon } from "lucide-react";
import { forwardRef, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ChangeEvent, type CSSProperties, type KeyboardEvent } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { platformLabel } from "../../../lib/format.js";
import { formatLocalProxy, runtimeLocalProxy } from "../../../lib/runtime-message.js";
import type { RoutingTab } from "../../../types.js";
import type { RoutingRule, RoutingRuleType } from "../../../../shared/types.js";
import { validateRoutingRuleValue } from "../../../../shared/validation.js";
import {
  Button,
  Callout,
  Card,
  CardHeader,
  cx,
  EmptyState,
  Icon,
  IconButton,
  Kbd,
  Mono,
  SearchInput,
  Switch,
  TabPanel,
  Tabs
} from "../../ui/index.js";
import { RunningApps, TunCard, UdpNote, type ProcessLoad } from "./AppsTools.js";
import {
  duplicateMessage,
  filterRules,
  findDuplicateRule,
  RULE_PAGE_SIZE,
  ruleMeta,
  rulesHeading,
  TAB_RULE_TYPE,
  tabCopy,
  validateRuleDraft
} from "./routing-model.js";
import type { RoutingController } from "./useRoutingController.js";

const TYPE_ICON: Record<RoutingRuleType, LucideIcon> = { domain: Globe, ip: Network, "process.name": AppWindow };
const TAB_ICON: Record<RoutingTab, LucideIcon> = { domains: Globe, ips: Network, apps: AppWindow };
const FLASH_MS = 720;

/** "Your rules": tabs per rule type, the add row, the list, import and export. */
export const RulesCard = forwardRef<HTMLElement, { ctl: RoutingController }>(function RulesCard({ ctl }, ref) {
  const { run, runtime, snapshot } = useAppData();
  const { tab, rules, platform } = ctl;
  const copy = tabCopy(tab, platform);
  const type = TAB_RULE_TYPE[tab];
  const fileInput = useRef<HTMLInputElement>(null);

  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const [errorKey, setErrorKey] = useState(0);
  const [flash, setFlash] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState({ key: "", count: RULE_PAGE_SIZE });
  const [reveal, setReveal] = useState<string>();
  const [processes, setProcesses] = useState<ProcessLoad>({ state: "idle" });
  const [processQuery, setProcessQuery] = useState("");
  const rowRefs = useRef(new Map<string, HTMLDivElement>());
  const flashTimer = useRef<number>();

  useEffect(() => () => window.clearTimeout(flashTimer.current), []);

  // A new tab starts with an empty add row: a value typed for one rule type is not checked as another.
  const previousTab = useRef(tab);
  useEffect(() => {
    if (previousTab.current !== tab) {
      previousTab.current = tab;
      setDraft("");
      setError("");
      setFlash(false);
      setReveal(undefined);
    }
  }, [tab]);

  const inTab = useMemo(() => rules.filter((rule) => rule.type === type), [rules, type]);
  const shown = useMemo(() => filterRules(rules, type, query), [query, rules, type]);
  const enabledInTab = inTab.filter((rule) => rule.enabled).length;
  // Paging restarts only for a new tab or search; adding or removing rules keeps the place.
  const pageKey = `${tab}\u0000${query.trim().toLowerCase()}`;
  const visibleCount = page.key === pageKey ? page.count : RULE_PAGE_SIZE;
  const visible = shown.slice(0, visibleCount);
  const remaining = Math.max(0, shown.length - visible.length);

  const counts = useMemo(() => {
    const result: Record<RoutingRuleType, number> = { domain: 0, ip: 0, "process.name": 0 };
    for (const rule of rules) {
      result[rule.type] += 1;
    }
    return result;
  }, [rules]);

  // Bring a just-added rule into view, even past the current page.
  useLayoutEffect(() => {
    if (!reveal) {
      return;
    }
    const index = shown.findIndex((rule) => rule.id === reveal);
    if (index < 0) {
      return;
    }
    if (index >= visibleCount) {
      setPage({ key: pageKey, count: index + 1 });
      return;
    }
    rowRefs.current.get(reveal)?.scrollIntoView({ block: "nearest" });
    setReveal(undefined);
  }, [pageKey, reveal, shown, visibleCount]);

  const addRule = (raw: string = draft): void => {
    const result = validateRuleDraft(type, raw, platform);
    if (result.error !== undefined) {
      setError(result.error);
      setErrorKey((key) => key + 1);
      return;
    }
    const duplicate = findDuplicateRule(rules, type, result.value, platform);
    if (duplicate) {
      setError(duplicateMessage(result.value, duplicate));
      setErrorKey((key) => key + 1);
      return;
    }
    const id = ctl.addRule(type, result.value);
    setDraft("");
    setError("");
    const needle = query.trim().toLowerCase();
    if (needle && !result.value.includes(needle)) {
      setQuery("");
    }
    setReveal(id);
  };

  const pickProcess = (name: string): void => {
    setDraft(name);
    setError("");
    setFlash(false);
    window.requestAnimationFrame(() => setFlash(true));
    window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(false), FLASH_MS);
  };

  const loadProcesses = useCallback((): void => {
    setProcesses((current) => (current.state === "loading" ? current : { state: "loading", previous: current.state === "loaded" ? current.names : undefined }));
    void run(() => api.listProcesses(), { background: true, errorTitle: "Couldn’t load running apps" }).then((names) => {
      setProcesses((current) => {
        if (names) {
          return { state: "loaded", names };
        }
        const previous = current.state === "loading" ? current.previous : undefined;
        return previous ? { state: "loaded", names: previous } : { state: "idle" };
      });
    });
  }, [run]);

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>): void => {
    if (event.key === "Enter") {
      event.preventDefault();
      addRule(event.currentTarget.value);
    }
  };

  const onFile = (event: ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) {
      void ctl.importFile(file);
    }
  };

  const proxy = runtimeLocalProxy(runtime);
  const showTun = tab === "apps" && snapshot.tunStatus.supported;
  const hasError = Boolean(error);
  const trimmedQuery = query.trim();

  return (
    <Card ref={ref} rise={3} aria-labelledby="rt-rules-title">
      <CardHeader
        level={2}
        titleId="rt-rules-title"
        icon={List}
        title="Your rules"
        sub="Sites, IP ranges and apps that go through the tunnel in Split tunnel. Turn a rule off to keep it for later."
        tools={
          <>
            <Button size="sm" icon={Upload} aria-haspopup="dialog" onClick={() => fileInput.current?.click()}>
              Import
            </Button>
            <Button size="sm" icon={Download} disabled={rules.length === 0} onClick={() => void ctl.exportRules()}>
              Export
            </Button>
            <input
              ref={fileInput}
              type="file"
              accept=".json,application/json"
              hidden
              tabIndex={-1}
              aria-label="Choose a routing rules file to import"
              onChange={onFile}
            />
          </>
        }
      />

      {ctl.mode === "proxy-all" && rules.length > 0 ? (
        <Callout tone="info" className="anim-swap" title="Full tunnel is on">
          Everything already goes through the tunnel, so these rules don’t change anything right now. They’re kept for Split tunnel.
        </Callout>
      ) : null}

      <Tabs
        id="rt"
        value={tab}
        onChange={ctl.setTab}
        ariaLabel="Rule type"
        options={[
          { value: "domains", label: "Domains", icon: TAB_ICON.domains, count: counts.domain },
          { value: "ips", label: "IPs", icon: TAB_ICON.ips, count: counts.ip },
          { value: "apps", label: "Apps", icon: TAB_ICON.apps, count: counts["process.name"] }
        ]}
      />

      <TabPanel id="rt" value={tab} className="stack rt-panel">
        {showTun ? <TunCard ctl={ctl} /> : null}

        {tab === "apps" && !ctl.steers ? (
          <Callout tone="info" title={`App rules are saved, but don’t steer traffic on ${platformLabel(platform)}`}>
            {proxy ? (
              <>
                Only apps set to use <Mono>{formatLocalProxy(proxy)}</Mono> go through the tunnel.
              </>
            ) : (
              "Only apps set to use the local proxy go through the tunnel. Connect shows its address."
            )}{" "}
            There’s no TUN adapter on {platformLabel(platform)}.
          </Callout>
        ) : null}

        <div className="rt-add">
          <label className="label" htmlFor="rt-new-rule">
            {copy.addLabel}
          </label>
          <div className="rt-add-row">
            <div className="rt-field" data-invalid={hasError} data-flash={flash}>
              <span className="rt-tag" aria-hidden="true">
                <Icon icon={TAB_ICON[tab]} />
                {copy.tag}
              </span>
              <input
                id="rt-new-rule"
                type="text"
                placeholder={copy.placeholder}
                value={draft}
                onChange={(event) => {
                  setDraft(event.target.value);
                  if (error) {
                    setError("");
                  }
                }}
                onKeyDown={handleKeyDown}
                aria-invalid={hasError || undefined}
                aria-describedby={hasError ? "rt-add-error rt-add-hint" : "rt-add-hint"}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button variant="primary" icon={Plus} className="rt-add-btn" onClick={() => addRule()}>
              Add
            </Button>
          </div>
          {hasError ? (
            <div className="error-text rt-err" id="rt-add-error" role="alert" key={errorKey}>
              <Icon icon={TriangleAlert} size="sm" />
              <span>{error}</span>
            </div>
          ) : null}
          <div className="hint rt-hint-row" id="rt-add-hint">
            <Kbd>↵</Kbd>
            <span>Enter adds it.</span>
            <span>{copy.hint}</span>
          </div>
        </div>

        {tab === "apps" ? (
          <RunningApps
            load={processes}
            onLoad={loadProcesses}
            query={processQuery}
            onQueryChange={setProcessQuery}
            appRules={inTab}
            platform={platform}
            onPick={pickProcess}
          />
        ) : null}

        <div className="stack" style={{ gap: 10 }}>
          <div className="rt-list-head">
            <span className="eyebrow" aria-live="polite">
              {rulesHeading(copy, inTab.length, enabledInTab, shown.length, query)}
            </span>
            <div className="rt-search">
              <SearchInput value={query} onValueChange={setQuery} placeholder={copy.search} aria-label={`Search ${copy.many}`} autoComplete="off" />
            </div>
          </div>

          {visible.length > 0 ? (
            <div className="rt-rules" role="list" aria-label={copy.listLabel}>
              {visible.map((rule, index) => (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  index={index}
                  leaving={ctl.leaving.has(rule.id)}
                  highlighted={ctl.highlighted === rule.id}
                  onToggle={ctl.toggleRule}
                  onDelete={ctl.deleteRule}
                  rowRef={(element) => {
                    if (element) {
                      rowRefs.current.set(rule.id, element);
                    } else {
                      rowRefs.current.delete(rule.id);
                    }
                  }}
                />
              ))}
            </div>
          ) : null}

          {inTab.length === 0 ? (
            <EmptyState icon={Plus} title={copy.emptyTitle} className="fade">
              {copy.emptyText}
            </EmptyState>
          ) : null}

          {inTab.length > 0 && shown.length === 0 ? (
            <EmptyState
              icon={Search}
              title={`Nothing matches “${trimmedQuery}”`}
              className="fade"
              action={
                <Button size="sm" onClick={() => setQuery("")}>
                  Clear search
                </Button>
              }
            >
              The search only looks inside this tab.
            </EmptyState>
          ) : null}

          {remaining > 0 ? (
            <div className="rt-more">
              <Button variant="ghost" size="sm" onClick={() => setPage({ key: pageKey, count: visibleCount + RULE_PAGE_SIZE })}>
                Show {Math.min(RULE_PAGE_SIZE, remaining)} more · {remaining} left
              </Button>
            </div>
          ) : null}
        </div>

        {tab === "apps" ? <UdpNote /> : null}
      </TabPanel>
    </Card>
  );
});

function RuleRow({
  rule,
  index,
  leaving,
  highlighted,
  onToggle,
  onDelete,
  rowRef
}: {
  rule: RoutingRule;
  index: number;
  leaving: boolean;
  highlighted: boolean;
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
  rowRef: (element: HTMLDivElement | null) => void;
}): JSX.Element {
  // A row that mounts highlighted plays the "new" animation instead of the
  // entrance rise; afterwards it keeps no animation so neither replays.
  const mountedHighlighted = useRef(highlighted);
  const stateText = rule.enabled ? "Enabled" : "Disabled";
  const valid = validateRoutingRuleValue(rule.type, rule.value).ok;
  const animation = highlighted ? "rt-rule-new" : mountedHighlighted.current ? undefined : "rise";
  return (
    <div
      ref={rowRef}
      className={cx("rt-rule", animation)}
      role="listitem"
      data-on={rule.enabled}
      data-valid={valid}
      data-leaving={leaving}
      style={{ "--d": Math.min(index, 10) } as CSSProperties}
    >
      <span className="rt-rule-ic" aria-hidden="true">
        <Icon icon={TYPE_ICON[rule.type]} size="sm" />
      </span>
      <span className="rt-rule-main">
        <span className="rt-rule-value">{rule.value}</span>
        <span className="rt-rule-meta">
          <span className="rt-state-inline">{stateText} · </span>
          {ruleMeta(rule)}
        </span>
      </span>
      <span className="rt-rule-state" aria-hidden="true">
        {stateText}
      </span>
      <Switch checked={rule.enabled} aria-label={`${rule.enabled ? "Disable" : "Enable"} rule ${rule.value}`} onCheckedChange={() => onToggle(rule.id)} />
      <IconButton icon={Trash2} label={`Delete rule ${rule.value}`} tooltip="Delete" className="rt-rule-del" onClick={() => onDelete(rule.id)} />
    </div>
  );
}
