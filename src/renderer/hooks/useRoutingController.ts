import { useEffect, useMemo, useRef, useState, type ChangeEvent, type Dispatch, type SetStateAction } from "react";
import { api } from "../api.js";
import { toErrorMessage } from "../lib/labels.js";
import type { RoutingSaveState } from "../types.js";
import { normalizeRuleValue, validateRoutingRuleValue } from "../../shared/validation.js";
import type { AppSnapshot, RoutingRule, RoutingRuleType } from "../../shared/types.js";

export function useRoutingController({
  snapshot,
  setSnapshot,
  setNotice,
  run
}: {
  snapshot: AppSnapshot | undefined;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setNotice: Dispatch<SetStateAction<string>>;
  run: (action: () => Promise<AppSnapshot | void>) => Promise<void>;
}) {
  const [ruleTab, setRuleTab] = useState<RoutingRuleType>("domain");
  const [ruleSearch, setRuleSearch] = useState("");
  const [ruleValue, setRuleValue] = useState("");
  const [ruleError, setRuleError] = useState("");
  const [routingDraft, setRoutingDraft] = useState<RoutingRule[]>([]);
  const [routingSaveState, setRoutingSaveState] = useState<RoutingSaveState>("idle");
  const [processSearch, setProcessSearch] = useState("");
  const [processes, setProcesses] = useState<string[]>([]);
  const routingSaveSeq = useRef(0);

  useEffect(() => {
    if (snapshot) {
      setRoutingDraft(snapshot.store.routingRules);
    }
  }, [snapshot?.store.routingRules]);

  const filteredRules = useMemo(
    () =>
      routingDraft.filter(
        (rule) =>
          rule.type === ruleTab &&
          (!ruleSearch.trim() || rule.value.toLowerCase().includes(ruleSearch.trim().toLowerCase()))
      ),
    [routingDraft, ruleSearch, ruleTab]
  );

  const filteredProcesses = useMemo(
    () =>
      processes.filter((name) =>
        processSearch.trim() ? name.toLowerCase().includes(processSearch.trim().toLowerCase()) : true
      ),
    [processSearch, processes]
  );

  function persistRoutingRules(nextRules: RoutingRule[], successMessage?: string): void {
    const sequence = routingSaveSeq.current + 1;
    routingSaveSeq.current = sequence;
    setRoutingSaveState("saving");
    void api
      .updateRoutingRules(nextRules)
      .then((next) => {
        if (routingSaveSeq.current !== sequence) {
          return;
        }
        setSnapshot(next);
        setRoutingSaveState("saved");
        if (successMessage) {
          setNotice(successMessage);
        }
      })
      .catch((error: unknown) => {
        if (routingSaveSeq.current !== sequence) {
          return;
        }
        setRoutingSaveState("error");
        setNotice(toErrorMessage(error));
      });
  }

  function updateRoutingDraft(mutator: (rules: RoutingRule[]) => RoutingRule[]): void {
    const next = mutator(routingDraft);
    setRoutingDraft(next);
    persistRoutingRules(next);
  }

  function addRule(): void {
    const validation = validateRoutingRuleValue(ruleTab, ruleValue);
    if (!validation.ok) {
      setRuleError(validation.message ?? "Invalid rule.");
      return;
    }

    const normalized = normalizeRuleValue(ruleTab, ruleValue);
    if (routingDraft.some((rule) => rule.type === ruleTab && rule.value === normalized)) {
      setRuleError("This rule already exists.");
      return;
    }

    const now = new Date().toISOString();
    updateRoutingDraft((rules) => [
      ...rules,
      {
        id: crypto.randomUUID(),
        type: ruleTab,
        value: normalized,
        enabled: true,
        createdAt: now,
        updatedAt: now
      }
    ]);
    setRuleValue("");
    setRuleError("");
  }

  function importRules(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as RoutingRule[];
        if (!Array.isArray(parsed)) {
          throw new Error("Import file must contain a rules array.");
        }
        const validRules = parsed.filter((rule) => validateRoutingRuleValue(rule.type, rule.value).ok);
        setRoutingDraft(validRules);
        persistRoutingRules(validRules, `Imported and saved ${validRules.length} valid rules.`);
      } catch (error) {
        setNotice(toErrorMessage(error));
      }
    };
    reader.readAsText(file);
    event.target.value = "";
  }

  function exportRules(): void {
    const blob = new Blob([`${JSON.stringify(routingDraft, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "shadow-ssh-routing-rules.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  function loadProcesses(): void {
    void run(async () => {
      setProcesses(await api.listProcesses());
    });
  }

  return {
    ruleTab,
    setRuleTab,
    ruleSearch,
    setRuleSearch,
    ruleValue,
    setRuleValue,
    ruleError,
    routingDraft,
    routingSaveState,
    processSearch,
    setProcessSearch,
    filteredRules,
    filteredProcesses,
    updateRoutingDraft,
    addRule,
    importRules,
    exportRules,
    loadProcesses
  };
}
