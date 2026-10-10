import { Undo2 } from "lucide-react";
import { createElement, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { describeError, errorText } from "../../../lib/errors.js";
import { isPreviewSession } from "../../../lib/connection.js";
import { formatCount, plural } from "../../../lib/format.js";
import type { RoutingTab } from "../../../types.js";
import { activeTargetName } from "../../shell/index.js";
import { Mono } from "../../ui/index.js";
import type {
  AppSnapshot,
  DesktopPlatform,
  RoutingDirectList,
  RoutingMode,
  RoutingMutationResult,
  RoutingProxyList,
  RoutingRule,
  RoutingRuleType
} from "../../../../shared/types.js";
import { exportRulesToFile, type ExportOutcome } from "./rule-export.js";
import {
  assertImportSize,
  describeSkipped,
  parseRuleImport,
  richTextToString,
  RuleImportError,
  rulesAfterImportUndo,
  type RuleImportPreview
} from "./rule-import.js";
import {
  connectionBadge,
  countTargets,
  cutsLastTargetWithPending,
  isLiveSession,
  listName,
  steersSystemTraffic,
  wouldCutLastTarget,
  type ConnectionBadge,
  type ListBusy,
  type ListKind,
  type RoutingTargets
} from "./routing-model.js";
import { useRoutingAutosave, type RoutingAutosave, type SaveOutcome } from "./useRoutingAutosave.js";

/** A change that would remove the last target of a running Split tunnel. */
export type PendingCut =
  | { kind: "toggle"; id: string }
  | { kind: "delete"; id: string }
  | { kind: "list"; list: ListKind }
  | { kind: "undo-import"; rules: RoutingRule[]; count: number };

export type RoutingDialog =
  | { kind: "mode-guard" }
  | { kind: "last-target"; pending: PendingCut }
  | { kind: "import"; preview: RuleImportPreview }
  | { kind: "viewer"; list: ListKind };

interface Drafts {
  rules?: RoutingRule[];
  mode?: RoutingMode;
  tun?: boolean;
}

const LEAVE_MS = 230;
const NEW_ROW_MS = 1600;

export interface RoutingController {
  snapshot: AppSnapshot;
  platform: DesktopPlatform;
  /** Rules and lists steer system traffic here (Windows). */
  steers: boolean;
  /** A session runs or is being built on the active transport. */
  live: boolean;
  /** Name of the server or profile the active session uses. */
  sessionName?: string;
  mode: RoutingMode;
  rules: RoutingRule[];
  proxyList: RoutingProxyList;
  directList: RoutingDirectList;
  targets: RoutingTargets;
  /** Split tunnel has nothing to route, so Connect is blocked. */
  blocked: boolean;
  connection: ConnectionBadge;
  tunEnabled: boolean;
  autosave: RoutingAutosave;
  tab: RoutingTab;
  setTab: (tab: RoutingTab) => void;
  dialog?: RoutingDialog;
  closeDialog: () => void;
  listBusy: Partial<Record<ListKind, ListBusy>>;
  listErrors: Partial<Record<ListKind, string>>;
  /** Rule ids playing their exit animation. */
  leaving: ReadonlySet<string>;
  /** Rule id to highlight as just added (or restored). */
  highlighted?: string;
  reconnecting: boolean;
  importBusy: boolean;

  pickMode: (mode: RoutingMode) => void;
  toggleList: (kind: ListKind) => void;
  refreshList: (kind: ListKind) => void;
  /** Try again after a failed download: refresh when there is a copy, else turn it on. */
  retryList: (kind: ListKind) => void;
  enableProxyList: () => void;
  openViewer: (kind: ListKind) => void;
  addRule: (type: RoutingRuleType, value: string) => string;
  toggleRule: (id: string) => void;
  deleteRule: (id: string) => void;
  guardSwitchAnyway: () => void;
  guardEnableList: () => void;
  lastTargetToFull: () => void;
  lastTargetConfirm: () => void;
  importFile: (file: File) => Promise<void>;
  confirmImport: (preview: RuleImportPreview) => Promise<void>;
  exportRules: () => Promise<ExportOutcome>;
  toggleTun: () => void;
  reconnectNow: () => Promise<void>;
}

export function useRoutingController(): RoutingController {
  const { snapshot, store, runtime, activeTransport, environment, run, toast, confirm, setSnapshot } = useAppData();
  const platform = environment.platform;
  const [drafts, setDrafts] = useState<Drafts>({});
  const [tab, setTab] = useState<RoutingTab>("domains");
  const [dialog, setDialog] = useState<RoutingDialog>();
  const [listBusy, setListBusyState] = useState<Partial<Record<ListKind, ListBusy>>>({});
  const [listErrors, setListErrors] = useState<Partial<Record<ListKind, string>>>({});
  const [leaving, setLeaving] = useState<ReadonlySet<string>>(new Set());
  const [highlighted, setHighlighted] = useState<string>();
  const [reconnecting, setReconnecting] = useState(false);
  const [importBusy, setImportBusy] = useState(false);

  const rules = drafts.rules ?? store.routingRules;
  const mode = drafts.mode ?? store.routingMode;
  const tunEnabled = drafts.tun ?? store.settings.tunDataplaneEnabled;
  const proxyList = store.routingProxyList;
  const directList = store.routingDirectList;
  const live = isLiveSession(runtime.state);
  const sessionName = activeTargetName(snapshot);
  const targets = useMemo(() => countTargets(rules, proxyList), [proxyList, rules]);
  const blocked = mode === "selected-rules" && targets.total === 0;

  // Handlers read the latest values through refs: several changes can land
  // before React renders again (fast toggles, an Undo during a save).
  const rulesRef = useRef(rules);
  const modeRef = useRef(mode);
  const liveRef = useRef(live);
  const proxyRef = useRef(proxyList);
  const directRef = useRef(directList);
  const nameRef = useRef(sessionName);
  /**
   * Changes already on their way that the refs above don't show yet: rules
   * playing their delete animation, and a list being turned off (its reply
   * waits for main to re-apply routing). The last-target guard counts them as
   * done, so two quick changes can't each pass it and leave nothing together.
   */
  const pendingDeletes = useRef(new Set<string>());
  const listsTurningOff = useRef(new Set<ListKind>());
  rulesRef.current = rules;
  modeRef.current = mode;
  liveRef.current = live;
  proxyRef.current = proxyList;
  directRef.current = directList;
  nameRef.current = sessionName;

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  /** The saved rules to build on; an Undo clicked after leaving the page reads them fresh. */
  const currentRules = useCallback(async (): Promise<RoutingRule[]> => {
    if (mounted.current) {
      return rulesRef.current;
    }
    return (await api.loadSnapshot()).store.routingRules;
  }, []);

  const timers = useRef(new Map<number, { fn: () => void; flush: boolean }>());
  /** Runs `fn` after `ms`; with `flush`, leaving the page runs it right away instead of dropping it. */
  const later = useCallback((ms: number, fn: () => void, flush = false): void => {
    const timer = window.setTimeout(() => {
      timers.current.delete(timer);
      fn();
    }, ms);
    timers.current.set(timer, { fn, flush });
  }, []);
  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const [timer, entry] of pending) {
        window.clearTimeout(timer);
        if (entry.flush) {
          entry.fn();
        }
      }
      pending.clear();
    };
  }, []);

  const commitRulesRef = useRef<(next: RoutingRule[]) => Promise<SaveOutcome>>();
  const autosave = useRoutingAutosave(setSnapshot, () => {
    // Re-saving the current rules re-applies the whole routing state.
    void commitRulesRef.current?.(rulesRef.current);
  });
  const { save, clearUnapplied } = autosave;

  useEffect(() => {
    if (!live) {
      clearUnapplied();
    }
  }, [clearUnapplied, live]);

  /* ---------- Saving ---------- */

  const rulesSeq = useRef(0);
  const commitRules = useCallback((next: RoutingRule[]): Promise<SaveOutcome> => {
    rulesRef.current = next;
    setDrafts((current) => ({ ...current, rules: next }));
    const token = ++rulesSeq.current;
    return save(() => api.updateRoutingRules(next), { retry: () => void commitRulesRef.current?.(rulesRef.current) }).then((outcome) => {
      if (outcome.ok && token === rulesSeq.current) {
        setDrafts((current) => ({ ...current, rules: undefined }));
      }
      return outcome;
    });
  }, [save]);
  commitRulesRef.current = commitRules;

  const modeSeq = useRef(0);
  const commitMode = useCallback((next: RoutingMode): Promise<SaveOutcome> => {
    modeRef.current = next;
    setDrafts((current) => ({ ...current, mode: next }));
    const token = ++modeSeq.current;
    const attempt = (): Promise<SaveOutcome> =>
      save(() => api.updateRoutingMode(next), { retry: () => void attempt() }).then((outcome) => {
        if (outcome.ok && token === modeSeq.current) {
          setDrafts((current) => ({ ...current, mode: undefined }));
        }
        return outcome;
      });
    return attempt();
  }, [save]);

  const tunSeq = useRef(0);
  const commitTun = useCallback((enabled: boolean): void => {
    setDrafts((current) => ({ ...current, tun: enabled }));
    const token = ++tunSeq.current;
    const attempt = (): void => {
      void save(() => api.updateSettings({ tunDataplaneEnabled: enabled }), { retry: attempt }).then((outcome) => {
        if (outcome.ok && token === tunSeq.current) {
          setDrafts((current) => ({ ...current, tun: undefined }));
        }
      });
    };
    attempt();
  }, [save]);

  /* ---------- Guards ---------- */

  const cutsLastTarget = useCallback((nextRules: readonly RoutingRule[], nextProxy?: RoutingProxyList): boolean => cutsLastTargetWithPending(
    modeRef.current,
    liveRef.current,
    { rules: rulesRef.current, proxyList: proxyRef.current },
    { rules: nextRules, proxyList: nextProxy },
    { deletingRuleIds: pendingDeletes.current, proxyListTurningOff: listsTurningOff.current.has("proxy") }
  ), []);

  /** Ends the session on purpose before a change that would leave Split tunnel empty. */
  const disconnectOnPurpose = useCallback(async (): Promise<boolean> => {
    if (!liveRef.current) {
      return true;
    }
    const result = await run(() => api.disconnect(), { errorTitle: "Couldn’t disconnect" });
    return result !== undefined;
  }, [run]);

  const toastDisconnected = useCallback((name: string | undefined): void => {
    toast({
      tone: "warning",
      title: name ? `Disconnected from ${name}` : "Disconnected",
      message: "Split tunnel had nothing left to route. Add a target, then connect again.",
      duration: 8000
    });
  }, [toast]);

  /* ---------- Domain lists ---------- */

  const setListBusy = useCallback((kind: ListKind, busy: ListBusy | undefined): void => {
    setListBusyState((current) => ({ ...current, [kind]: busy }));
  }, []);
  const setListError = useCallback((kind: ListKind, error: string | undefined): void => {
    setListErrors((current) => ({ ...current, [kind]: error }));
  }, []);

  const runListOperation = useCallback(async (
    kind: ListKind,
    busy: ListBusy,
    operation: () => Promise<RoutingMutationResult>,
    quiet: boolean
  ): Promise<SaveOutcome> => {
    setListBusy(kind, busy);
    setListError(kind, undefined);
    const outcome = await save(operation, { inlineErrors: true, quiet });
    if (outcome.ok && outcome.snapshot) {
      // Ahead of the re-render, so a guard that runs next sees the saved list.
      proxyRef.current = outcome.snapshot.store.routingProxyList;
      directRef.current = outcome.snapshot.store.routingDirectList;
    }
    setListBusy(kind, undefined);
    if (!outcome.ok) {
      setListError(kind, errorText(outcome.error));
    }
    return outcome;
  }, [save, setListBusy, setListError]);

  const listOf = useCallback((kind: ListKind) => (kind === "proxy" ? proxyRef.current : directRef.current), []);

  const listOn = useCallback(async (kind: ListKind): Promise<boolean> => {
    const list = listOf(kind);
    const download = list.domains.length === 0;
    const outcome = await runListOperation(
      kind,
      download ? "downloading" : "turning-on",
      () => (kind === "proxy" ? api.updateRoutingProxyListEnabled(true) : api.updateRoutingDirectListEnabled(true)),
      false
    );
    if (outcome.ok && download && outcome.snapshot) {
      const next = kind === "proxy" ? outcome.snapshot.store.routingProxyList : outcome.snapshot.store.routingDirectList;
      toast({
        tone: "success",
        title: `${listName(kind)} is on`,
        message: `${plural(next.domains.length, "domain")} downloaded. ${kind === "proxy" ? "They go through the tunnel." : "They stay direct."}`
      });
    }
    return outcome.ok;
  }, [listOf, runListOperation, toast]);

  const listOff = useCallback(async (kind: ListKind): Promise<SaveOutcome> => {
    listsTurningOff.current.add(kind);
    try {
      return await runListOperation(
        kind,
        "turning-off",
        () => (kind === "proxy" ? api.updateRoutingProxyListEnabled(false) : api.updateRoutingDirectListEnabled(false)),
        false
      );
    } finally {
      listsTurningOff.current.delete(kind);
    }
  }, [runListOperation]);

  const toggleList = useCallback((kind: ListKind): void => {
    const list = listOf(kind);
    if (!list.enabled) {
      void listOn(kind);
      return;
    }
    if (kind === "proxy" && cutsLastTarget(rulesRef.current, { ...list, enabled: false } as RoutingProxyList)) {
      setDialog({ kind: "last-target", pending: { kind: "list", list: kind } });
      return;
    }
    void listOff(kind);
  }, [cutsLastTarget, listOf, listOff, listOn]);

  const refreshList = useCallback((kind: ListKind): void => {
    const hadData = listOf(kind).domains.length > 0;
    void runListOperation(
      kind,
      hadData ? "refreshing" : "downloading",
      () => (kind === "proxy" ? api.refreshRoutingProxyList() : api.refreshRoutingDirectList()),
      true
    ).then((outcome) => {
      if (!outcome.ok || !outcome.snapshot) {
        return;
      }
      const next = kind === "proxy" ? outcome.snapshot.store.routingProxyList : outcome.snapshot.store.routingDirectList;
      toast({
        tone: "success",
        title: `${listName(kind)} ${hadData ? "refreshed" : "downloaded"}`,
        message: `${plural(next.domains.length, "domain")}. ${next.enabled ? "Already in use." : "Turn the list on to use them."}`
      });
    });
  }, [listOf, runListOperation, toast]);

  const retryList = useCallback((kind: ListKind): void => {
    const list = listOf(kind);
    if (list.domains.length > 0) {
      refreshList(kind);
    } else {
      void listOn(kind);
    }
  }, [listOf, listOn, refreshList]);

  const enableProxyList = useCallback((): void => {
    void listOn("proxy");
  }, [listOn]);

  const openViewer = useCallback((kind: ListKind): void => setDialog({ kind: "viewer", list: kind }), []);

  /* ---------- Mode ---------- */

  const pickMode = useCallback((next: RoutingMode): void => {
    if (next === modeRef.current) {
      return;
    }
    if (next === "selected-rules" && countTargets(rulesRef.current, proxyRef.current).total === 0) {
      setDialog({ kind: "mode-guard" });
      return;
    }
    void commitMode(next);
  }, [commitMode]);

  const guardSwitchAnyway = useCallback((): void => {
    setDialog(undefined);
    const wasLive = liveRef.current;
    const name = nameRef.current;
    void (async () => {
      if (!(await disconnectOnPurpose())) {
        return;
      }
      const outcome = await commitMode("selected-rules");
      if (outcome.ok && wasLive) {
        toastDisconnected(name);
      }
    })();
  }, [commitMode, disconnectOnPurpose, toastDisconnected]);

  const guardEnableList = useCallback((): void => {
    setDialog(undefined);
    void (async () => {
      if (await listOn("proxy")) {
        await commitMode("selected-rules");
      }
    })();
  }, [commitMode, listOn]);

  /* ---------- Rules ---------- */

  const highlight = useCallback((id: string): void => {
    setHighlighted(id);
    later(NEW_ROW_MS, () => setHighlighted((current) => (current === id ? undefined : current)));
  }, [later]);

  const addRule = useCallback((type: RoutingRuleType, value: string): string => {
    const now = new Date().toISOString();
    const rule: RoutingRule = { id: crypto.randomUUID(), type, value, enabled: true, createdAt: now, updatedAt: now };
    void commitRules([...rulesRef.current, rule]);
    highlight(rule.id);
    return rule.id;
  }, [commitRules, highlight]);

  const setRuleEnabled = useCallback((id: string, enabled: boolean): void => {
    const now = new Date().toISOString();
    void commitRules(rulesRef.current.map((rule) => (rule.id === id ? { ...rule, enabled, updatedAt: now } : rule)));
  }, [commitRules]);

  const toggleRule = useCallback((id: string): void => {
    const rule = rulesRef.current.find((candidate) => candidate.id === id);
    if (!rule || pendingDeletes.current.has(id)) {
      return;
    }
    const next = rulesRef.current.map((candidate) => (candidate.id === id ? { ...candidate, enabled: !candidate.enabled } : candidate));
    if (cutsLastTarget(next)) {
      setDialog({ kind: "last-target", pending: { kind: "toggle", id } });
      return;
    }
    setRuleEnabled(id, !rule.enabled);
  }, [cutsLastTarget, setRuleEnabled]);

  const restoreRule = useCallback(async (rule: RoutingRule, index: number): Promise<void> => {
    const current = await currentRules();
    if (current.some((candidate) => candidate.id === rule.id)) {
      return;
    }
    const next = [...current];
    next.splice(Math.min(index, next.length), 0, rule);
    void commitRules(next);
    highlight(rule.id);
  }, [commitRules, currentRules, highlight]);

  const removeRule = useCallback((id: string): Promise<void> => new Promise((resolve) => {
    const index = rulesRef.current.findIndex((rule) => rule.id === id);
    const rule = rulesRef.current[index];
    if (!rule) {
      resolve();
      return;
    }
    pendingDeletes.current.add(id);
    setLeaving((current) => new Set(current).add(id));
    later(LEAVE_MS, () => {
      setLeaving((current) => {
        const next = new Set(current);
        next.delete(id);
        return next;
      });
      void commitRules(rulesRef.current.filter((candidate) => candidate.id !== id));
      pendingDeletes.current.delete(id);
      toast({
        tone: "info",
        title: "Rule deleted",
        message: createElement(Mono, { children: rule.value }),
        action: { label: "Undo", icon: Undo2, placement: "side", onClick: () => restoreRule(rule, index) }
      });
      resolve();
    }, true);
  }), [commitRules, later, restoreRule, toast]);

  const deleteRule = useCallback((id: string): void => {
    if (pendingDeletes.current.has(id)) {
      return;
    }
    if (cutsLastTarget(rulesRef.current.filter((rule) => rule.id !== id))) {
      setDialog({ kind: "last-target", pending: { kind: "delete", id } });
      return;
    }
    void removeRule(id);
  }, [cutsLastTarget, removeRule]);

  const applyPending = useCallback(async (pending: PendingCut): Promise<void> => {
    if (pending.kind === "toggle") {
      setRuleEnabled(pending.id, false);
    } else if (pending.kind === "delete") {
      await removeRule(pending.id);
    } else if (pending.kind === "undo-import") {
      await commitRules(pending.rules);
    } else {
      await listOff(pending.list);
    }
  }, [commitRules, listOff, removeRule, setRuleEnabled]);

  const lastTargetToFull = useCallback((): void => {
    if (dialog?.kind !== "last-target") {
      return;
    }
    const { pending } = dialog;
    const name = nameRef.current;
    setDialog(undefined);
    void (async () => {
      const outcome = await commitMode("proxy-all");
      if (!outcome.ok) {
        return;
      }
      await applyPending(pending);
      toast({
        tone: "info",
        title: "Switched to Full tunnel",
        message: `Everything goes through ${name ?? "the tunnel"}, so the connection stays up.`
      });
    })();
  }, [applyPending, commitMode, dialog, toast]);

  const lastTargetConfirm = useCallback((): void => {
    if (dialog?.kind !== "last-target") {
      return;
    }
    const { pending } = dialog;
    const name = nameRef.current;
    setDialog(undefined);
    void (async () => {
      if (!(await disconnectOnPurpose())) {
        return;
      }
      await applyPending(pending);
      toastDisconnected(name);
    })();
  }, [applyPending, dialog, disconnectOnPurpose, toastDisconnected]);

  /* ---------- Import and export ---------- */

  /**
   * Undo for an import: the imported rules go and the previous ones come
   * back, while rules added since stay. Like any other change it asks first
   * when the result would leave a running Split tunnel with nothing to route.
   */
  const undoImport = useCallback(async (imported: readonly RoutingRule[], previous: readonly RoutingRule[]): Promise<void> => {
    const rebuild = (current: readonly RoutingRule[]): RoutingRule[] => rulesAfterImportUndo(imported, previous, current);
    if (mounted.current) {
      const next = rebuild(rulesRef.current);
      if (cutsLastTarget(next)) {
        setDialog({ kind: "last-target", pending: { kind: "undo-import", rules: next, count: imported.length } });
        return;
      }
      await commitRules(next);
      return;
    }
    // Clicked after leaving Routing: judge it against what is saved now.
    const fresh = await api.loadSnapshot();
    const next = rebuild(fresh.store.routingRules);
    const cut = wouldCutLastTarget(
      fresh.store.routingMode,
      isLiveSession(fresh.runtime.state),
      countTargets(fresh.store.routingRules, fresh.store.routingProxyList),
      countTargets(next, fresh.store.routingProxyList)
    );
    if (!cut) {
      await commitRules(next);
      return;
    }
    const name = activeTargetName(fresh);
    const confirmed = await confirm({
      eyebrow: "Routing",
      tone: "warn",
      title: "Undo the import?",
      description: `Your previous rules have no enabled target, so Split tunnel would have nothing left to send. Rather than quietly sending everything direct, Shadow disconnects ${name ?? "the tunnel"}.`,
      confirmLabel: "Undo and disconnect",
      cancelLabel: "Keep imported rules",
      errorTitle: "Couldn’t disconnect",
      onConfirm: async () => {
        setSnapshot(await api.disconnect());
      }
    });
    if (confirmed && (await commitRules(next)).ok) {
      toastDisconnected(name);
    }
  }, [commitRules, confirm, cutsLastTarget, setSnapshot, toastDisconnected]);

  const importFile = useCallback(async (file: File): Promise<void> => {
    let preview: RuleImportPreview;
    try {
      assertImportSize(file);
      preview = parseRuleImport(await file.text(), { name: file.name, size: file.size });
    } catch (error) {
      const described = error instanceof RuleImportError
        ? { message: error.message, technical: error.technical }
        : describeError(error);
      toast({ tone: "error", title: "Couldn’t import rules", message: described.message, details: described.technical });
      return;
    }
    if (preview.rules.length === 0) {
      const skipped = describeSkipped(preview.skipped);
      toast({
        tone: "error",
        title: "Nothing to import",
        message: `${file.name} has no rules Shadow can use.${skipped ? ` ${richTextToString(skipped)}` : ""} Your rules stay as they are.`
      });
      return;
    }
    setDialog({ kind: "import", preview });
  }, [toast]);

  const confirmImport = useCallback(async (preview: RuleImportPreview): Promise<void> => {
    const previous = rulesRef.current;
    const name = nameRef.current;
    setImportBusy(true);
    try {
      const cut = cutsLastTarget(preview.rules);
      if (cut && !(await disconnectOnPurpose())) {
        return;
      }
      const outcome = await commitRules(preview.rules);
      setDialog(undefined);
      if (!outcome.ok) {
        return;
      }
      const count = preview.rules.length;
      toast({
        tone: "success",
        title: `Imported ${plural(count, "rule")}`,
        message: previous.length > 0 ? `Your previous ${plural(previous.length, "rule was", "rules were")} replaced.` : `From ${preview.fileName}.`,
        action: previous.length > 0
          ? { label: "Undo", icon: Undo2, placement: "side", onClick: () => undoImport(preview.rules, previous) }
          : undefined
      });
      if (cut) {
        toastDisconnected(name);
      }
    } finally {
      setImportBusy(false);
    }
  }, [commitRules, cutsLastTarget, disconnectOnPurpose, toast, toastDisconnected, undoImport]);

  const exportRules = useCallback(async (): Promise<ExportOutcome> => {
    const current = rulesRef.current;
    try {
      const outcome = await exportRulesToFile(current);
      if (outcome.saved) {
        toast({ tone: "success", title: `Exported ${plural(current.length, "rule")}`, message: `Saved as ${outcome.fileName}.` });
      }
      return outcome;
    } catch (error) {
      const described = describeError(error, { title: "Couldn’t export rules" });
      toast({ tone: "error", title: described.title, message: described.message, details: described.technical });
      return { saved: false };
    }
  }, [toast]);

  /* ---------- TUN ---------- */

  const toggleTun = useCallback((): void => commitTun(!tunEnabled), [commitTun, tunEnabled]);

  const reconnectNow = useCallback(async (): Promise<void> => {
    const transport = activeTransport;
    const name = nameRef.current;
    setReconnecting(true);
    try {
      const stopped = await run(() => api.disconnect(), { errorTitle: "Couldn’t reconnect" });
      if (!stopped) {
        return;
      }
      const next = await run(() => (transport === "xray" ? api.connectProxy() : api.connect()), { errorTitle: "Couldn’t reconnect" });
      if (!next || next.runtime.state !== "Connected") {
        return;
      }
      const tun = next.tunStatus;
      const ok = !tun.enabled || tun.active;
      toast({
        tone: ok ? "success" : "warning",
        title: name ? `Reconnected to ${name}` : "Reconnected",
        message: !tun.enabled
          ? "App rules now use the Windows proxy."
          : tun.active
            ? "The TUN adapter is carrying app traffic."
            : "The TUN adapter still can’t start. Open How to enable to see what’s missing.",
        duration: ok ? undefined : 8000
      });
    } finally {
      setReconnecting(false);
    }
  }, [activeTransport, run, toast]);

  const closeDialog = useCallback((): void => setDialog(undefined), []);

  const connection = connectionBadge({
    state: runtime.state,
    preview: isPreviewSession(runtime),
    platform,
    targetName: sessionName,
    blocked
  });

  return {
    snapshot,
    platform,
    steers: steersSystemTraffic(platform),
    live,
    sessionName,
    mode,
    rules,
    proxyList,
    directList,
    targets,
    blocked,
    connection,
    tunEnabled,
    autosave,
    tab,
    setTab,
    dialog,
    closeDialog,
    listBusy,
    listErrors,
    leaving,
    highlighted,
    reconnecting,
    importBusy,
    pickMode,
    toggleList,
    refreshList,
    retryList,
    enableProxyList,
    openViewer,
    addRule,
    toggleRule,
    deleteRule,
    guardSwitchAnyway,
    guardEnableList,
    lastTargetToFull,
    lastTargetConfirm,
    importFile,
    confirmImport,
    exportRules,
    toggleTun,
    reconnectNow
  };
}

/** "1,982 domains in use" across the enabled lists. */
export function listsInUseText(proxyList: RoutingProxyList, directList: RoutingDirectList): string | undefined {
  const sum = (proxyList.enabled ? proxyList.domains.length : 0) + (directList.enabled ? directList.domains.length : 0);
  return sum > 0 ? `${formatCount(sum)} domains in use` : undefined;
}
