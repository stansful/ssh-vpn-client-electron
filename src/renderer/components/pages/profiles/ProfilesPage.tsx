import { ChevronDown, Copy, Filter, Info, Plus, Search, Upload, X } from "lucide-react";
import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, useTransition, type CSSProperties } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { useNavigation } from "../../../hooks/useNavigation.js";
import { sliceRenderPage, nextRenderPageCount } from "../../../lib/render-page.js";
import type { AppSnapshot, ProxyProfile } from "../../../../shared/types.js";
import type { PageProps } from "../../../types.js";
import { activeTargetName, PageHeader } from "../../shell/index.js";
import { Button, Callout, cx, EmptyState, LinkButton } from "../../ui/index.js";
import { AddProfileDialog } from "./AddProfileDialog.js";
import { ImportLinksDialog } from "./ImportLinksDialog.js";
import { ProfileCard } from "./ProfileCard.js";
import {
  bulkRemoveCopy,
  copiedLinkCopy,
  copyLinkFailedCopy,
  countProfiles,
  currentSelection,
  describeRefreshFailure,
  filterEmptyCopy,
  filterProfiles,
  goneSelectCopy,
  moreBlockCopy,
  noMatchCopy,
  PROFILE_PAGE_SIZE,
  profileSearchText,
  publicListInfo,
  publicListMeta,
  removeBlockedCopy,
  removedOneCopy,
  removedUnpinnedCopy,
  renamedNotice,
  renameFailedTitle,
  resultsSummary,
  sessionWouldStop,
  summarizeRefresh,
  unsupportedPart,
  unsupportedSelectCopy,
  xraySessionOf,
  type BulkRemoveCopy,
  type ProfileFilter,
  type RefreshFailure
} from "./profile-presenter.js";
import { ProfilesOnboarding, ProfilesToolbar } from "./ProfilesToolbar.js";
import { RemoveProfileDialog, RemoveUnpinnedDialog } from "./RemoveDialogs.js";

/** Length of the card exit animation (`pf-leave`). */
const LEAVE_MS = 340;
/** Warnings about a single click don't need to stay until closed. */
const NOTICE_MS = 8000;

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function withProfiles(snapshot: AppSnapshot, update: (profile: ProxyProfile) => ProxyProfile, selectedId?: string | null): AppSnapshot {
  return {
    ...snapshot,
    store: {
      ...snapshot.store,
      selectedProxyProfileId: selectedId === undefined ? snapshot.store.selectedProxyProfileId : selectedId ?? undefined,
      proxyProfiles: snapshot.store.proxyProfiles.map(update)
    }
  };
}

/** Optimistic local selection (the card lights up before the save returns). */
function withSelection(snapshot: AppSnapshot, id: string | undefined): AppSnapshot {
  return withProfiles(snapshot, (profile) => (profile.isSelected === (profile.id === id) ? profile : { ...profile, isSelected: profile.id === id }), id ?? null);
}

function withPin(snapshot: AppSnapshot, id: string, pinned: boolean): AppSnapshot {
  return withProfiles(snapshot, (profile) => (profile.id === id && profile.isPinned !== pinned ? { ...profile, isPinned: pinned } : profile));
}

/** Optimistic rename. With `from`, only while the profile still has that name (a later rename wins). */
function withName(snapshot: AppSnapshot, id: string, name: string, from?: string): AppSnapshot {
  return withProfiles(snapshot, (profile) =>
    profile.id === id && profile.name !== name && (from === undefined || profile.name === from) ? { ...profile, name } : profile
  );
}

type Removal = { kind: "one"; profile: ProxyProfile } | { kind: "bulk" };

/**
 * Xray profiles (Profiles.dc.html): the library of share-link profiles, the
 * public list, and the Add / Import / Remove dialogs (Dialogs.dc.html).
 */
export function ProfilesPage({ intent }: PageProps): JSX.Element {
  const app = useAppData();
  const { snapshot, store, runtime, activeTransport, environment, run, toast, setSnapshot, navigate, updateSettings } = app;
  const { clearIntent } = useNavigation();

  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [filter, setFilter] = useState<ProfileFilter>("all");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshFailure, setRefreshFailure] = useState<RefreshFailure>();
  const [addOpen, setAddOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importPrefill, setImportPrefill] = useState<{ text: string; seq: number }>();
  const [removal, setRemoval] = useState<Removal>();
  const [removalOpen, setRemovalOpen] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [removeError, setRemoveError] = useState<unknown>();
  const [exiting, setExiting] = useState<{ list: readonly ProxyProfile[]; ids: ReadonlySet<string> }>();
  // `seq` re-renders the live text, so a second identical notice is read out too.
  const [renameNotice, setRenameNotice] = useState({ text: "", seq: 0 });
  // Search text of cards renamed during this search, from before the rename: they keep
  // matching it until the search changes, so the grid doesn't reflow under the click
  // that saved the name or drop the card Enter hands focus back to.
  const [renamedInSearch, setRenamedInSearch] = useState<ReadonlyMap<string, string>>();
  const [morePending, startMore] = useTransition();

  const changeQuery = useCallback((next: string): void => {
    setQuery(next);
    setRenamedInSearch(undefined);
  }, []);

  const profiles = store.proxyProfiles;
  const session = useMemo(
    () => xraySessionOf(activeTransport, runtime),
    // Only the fields the session reads; runtime messages change often.
    [activeTransport, runtime.state, runtime.transport, runtime.realTunnelAvailable, runtime.activeConfigId, runtime.activeConfigName]
  );

  // Latest values for stable callbacks (cards are memoized).
  const latest = useRef({ store, session, refreshing, removing, query: deferredQuery });
  latest.current = { store, session, refreshing, removing, query: deferredQuery };
  const exitTimer = useRef<number>();
  useEffect(() => () => window.clearTimeout(exitTimer.current), []);

  const pageBusy = refreshing || removing;
  const counts = useMemo(() => countProfiles(profiles), [profiles]);

  // While cards play their exit, render the previous list with the removed ones marked.
  const displayProfiles = useMemo(() => {
    if (!exiting) {
      return profiles;
    }
    const current = new Map(profiles.map((profile) => [profile.id, profile]));
    const previousIds = new Set(exiting.list.map((profile) => profile.id));
    return [...exiting.list.map((profile) => current.get(profile.id) ?? profile), ...profiles.filter((profile) => !previousIds.has(profile.id))];
  }, [exiting, profiles]);

  const searchIndex = useMemo(() => new Map(profiles.map((profile) => [profile.id, profileSearchText(profile)])), [profiles]);
  const visible = useMemo(
    () =>
      filterProfiles(displayProfiles, filter, deferredQuery, (profile) => {
        const text = searchIndex.get(profile.id) ?? profileSearchText(profile);
        const before = renamedInSearch?.get(profile.id);
        return before === undefined ? text : `${text}\n${before}`;
      }),
    [deferredQuery, displayProfiles, filter, renamedInSearch, searchIndex]
  );

  // "Show more" resets when the search, the filter or the number of profiles changes.
  const pageKey = `${filter}\u0000${deferredQuery.trim()}\u0000${profiles.length}`;
  const [paging, setPaging] = useState({ key: pageKey, count: PROFILE_PAGE_SIZE });
  const limit = paging.key === pageKey ? paging.count : PROFILE_PAGE_SIZE;
  const shown = useMemo(() => sliceRenderPage(visible, limit), [limit, visible]);

  // After Show more, keyboard focus moves to the first card it added.
  const gridRef = useRef<HTMLDivElement>(null);
  const focusCardAt = useRef<number>();
  useEffect(() => {
    const index = focusCardAt.current;
    if (index === undefined || morePending) {
      return;
    }
    focusCardAt.current = undefined;
    gridRef.current?.querySelectorAll<HTMLElement>(".pf-hit")[index]?.focus({ preventScroll: true });
  }, [morePending, shown]);

  const selectedId = store.selectedProxyProfileId;
  // F2 is a rename habit on Windows and Linux; on macOS it works but isn't hinted.
  const renameKeyHint = environment.platform === "windows" || environment.platform === "linux";

  const playExit = useCallback((list: readonly ProxyProfile[], ids: readonly string[], then: () => void): void => {
    window.clearTimeout(exitTimer.current);
    if (prefersReducedMotion() || ids.length === 0) {
      setExiting(undefined);
      then();
      return;
    }
    setExiting({ list, ids: new Set(ids) });
    exitTimer.current = window.setTimeout(() => {
      setExiting(undefined);
      then();
    }, LEAVE_MS);
  }, []);

  // ---------- actions ----------

  const refresh = useCallback(async (): Promise<void> => {
    if (latest.current.refreshing || latest.current.removing) {
      return;
    }
    // Guard a double click before the next render updates `latest`.
    latest.current.refreshing = true;
    setRefreshing(true);
    const before = latest.current.store;
    try {
      // Background: a refresh can take 30 s and must not block Connect.
      const response = await run(() => api.refreshProxyProfiles(), { background: true, silent: true, rethrow: true });
      if (response) {
        setRefreshFailure(undefined);
        const summary = summarizeRefresh(before, response.snapshot.store, response.result);
        toast({ id: "public-list-refresh", tone: summary.tone, title: summary.title, message: summary.message });
      }
    } catch (error) {
      const failure = describeRefreshFailure(error);
      setRefreshFailure({ at: new Date(), reason: failure.reason });
      toast({ id: "public-list-refresh", tone: "error", title: "Couldn’t refresh the public list", message: failure.message, details: failure.technical });
    } finally {
      setRefreshing(false);
    }
  }, [run, toast]);

  const selectProfile = useCallback(
    (profile: ProxyProfile): void => {
      if (unsupportedPart(profile)) {
        toast({ id: "profile-select", tone: "warning", duration: NOTICE_MS, ...unsupportedSelectCopy(profile) });
        return;
      }
      const previous = latest.current.store.selectedProxyProfileId;
      if (previous === profile.id) {
        return;
      }
      setSnapshot((current) => withSelection(current, profile.id));
      if (profile.isStale) {
        toast({ id: "profile-select", tone: "info", ...goneSelectCopy(profile) });
      }
      void run(() => api.selectProxyProfile(profile.id), { background: true, errorTitle: `Couldn’t select ${profile.name}` }).then((result) => {
        if (!result) {
          setSnapshot((current) => (current.store.selectedProxyProfileId === profile.id ? withSelection(current, previous) : current));
        }
      });
    },
    [run, setSnapshot, toast]
  );

  const togglePin = useCallback(
    (profile: ProxyProfile): void => {
      const pinned = !profile.isPinned;
      setSnapshot((current) => withPin(current, profile.id, pinned));
      void run(() => api.toggleProxyProfilePin(profile.id), {
        background: true,
        errorTitle: pinned ? `Couldn’t pin ${profile.name}` : `Couldn’t unpin ${profile.name}`
      }).then((result) => {
        if (!result) {
          setSnapshot((current) => withPin(current, profile.id, !pinned));
        }
      });
    },
    [run, setSnapshot]
  );

  const renameProfile = useCallback(
    (profile: ProxyProfile, name: string): void => {
      if (name === profile.name) {
        return;
      }
      if (latest.current.query.trim()) {
        setRenamedInSearch((current) => (current?.has(profile.id) ? current : new Map(current).set(profile.id, profileSearchText(profile))));
      }
      // A blank name waits for the main process, which reads the name in the link.
      if (name) {
        setSnapshot((current) => withName(current, profile.id, name));
      }
      void run(() => api.renameProxyProfile(profile.id, name), { background: true, errorTitle: renameFailedTitle(profile) }).then((result) => {
        if (!result) {
          if (name) {
            setSnapshot((current) => withName(current, profile.id, profile.name, name));
          }
          return;
        }
        const renamed = result.store.proxyProfiles.find((candidate) => candidate.id === profile.id);
        if (renamed && renamed.name !== profile.name) {
          setRenameNotice((current) => ({ text: renamedNotice(renamed.name), seq: current.seq + 1 }));
        }
      });
    },
    [run, setSnapshot]
  );

  // The main process writes the link to the clipboard; it never reaches this page.
  const copyLink = useCallback(
    (profile: ProxyProfile): void => {
      void run(() => api.copyProxyProfileLink(profile.id), { background: true, silent: true, rethrow: true })
        .then((copied) => {
          if (!copied) {
            throw new Error("The clipboard didn’t accept the link. Try again.");
          }
          toast({ id: "profile-copy-link", tone: "success", icon: Copy, ...copiedLinkCopy(profile) });
        })
        .catch((error: unknown) => {
          toast({ id: "profile-copy-link", tone: "error", ...copyLinkFailedCopy(error) });
        });
    },
    [run, toast]
  );

  const askRemove = useCallback(
    (profile: ProxyProfile): void => {
      const { session: current, refreshing: isRefreshing, removing: isRemoving } = latest.current;
      if (isRefreshing || isRemoving) {
        return;
      }
      if (current && current.profileId === profile.id) {
        toast({ id: "profile-remove-blocked", tone: "warning", duration: NOTICE_MS, ...removeBlockedCopy(profile, current) });
        return;
      }
      setRemoval({ kind: "one", profile });
      setRemoveError(undefined);
      setRemovalOpen(true);
    },
    [toast]
  );

  const askRemoveUnpinned = useCallback((): void => {
    const { refreshing: isRefreshing, removing: isRemoving, store: current } = latest.current;
    if (isRefreshing || isRemoving || countProfiles(current.proxyProfiles).unpinned === 0) {
      return;
    }
    setRemoval({ kind: "bulk" });
    setRemoveError(undefined);
    setRemovalOpen(true);
  }, []);

  const closeRemoval = (): void => {
    if (!removing) {
      setRemovalOpen(false);
    }
  };

  const confirmRemoval = async (): Promise<void> => {
    if (!removal || latest.current.removing) {
      return;
    }
    const before = latest.current.store;
    const stopsXray = removal.kind === "bulk" && sessionWouldStop(latest.current.session);
    latest.current.removing = true;
    setRemoving(true);
    setRemoveError(undefined);
    try {
      if (removal.kind === "one") {
        const { profile } = removal;
        const next = await run(() => api.deleteProxyProfile(profile.id), { silent: true, rethrow: true });
        if (!next) {
          return;
        }
        setRemovalOpen(false);
        const copy = removedOneCopy(profile, before, next.store);
        playExit(before.proxyProfiles, [profile.id], () => toast({ tone: "success", ...copy }));
      } else {
        const removedIds = before.proxyProfiles.filter((profile) => !profile.isPinned).map((profile) => profile.id);
        const beforeCounts = countProfiles(before.proxyProfiles);
        const next = await run(() => api.deleteUnpinnedProxyProfiles(), { silent: true, rethrow: true });
        if (!next) {
          return;
        }
        setRemovalOpen(false);
        const copy = removedUnpinnedCopy(beforeCounts.unpinned, beforeCounts.pinned, stopsXray);
        playExit(before.proxyProfiles, removedIds, () => toast({ tone: "success", ...copy }));
      }
    } catch (error) {
      setRemoveError(error);
    } finally {
      setRemoving(false);
    }
  };

  const openImport = useCallback((text?: string): void => {
    if (text) {
      setImportPrefill((current) => ({ text, seq: (current?.seq ?? 0) + 1 }));
    }
    setImportOpen(true);
  }, []);

  const openConnect = (): void => {
    if (store.settings.activeGlobalTab !== "xray") {
      // Open Connect on the Xray tab: that's where this selection shows.
      setSnapshot((current) => ({ ...current, store: { ...current.store, settings: { ...current.store.settings, activeGlobalTab: "xray" } } }));
      void updateSettings({ activeGlobalTab: "xray" });
    }
    navigate("connect");
  };

  useEffect(() => {
    if (!intent) {
      return;
    }
    if (intent.type === "add-profile") {
      setImportOpen(false);
      setAddOpen(true);
      clearIntent();
    } else if (intent.type === "import-profiles") {
      setAddOpen(false);
      setImportOpen(true);
      clearIntent();
    }
  }, [clearIntent, intent]);

  // ---------- derived copy ----------

  const libraryEmpty = displayProfiles.length === 0;
  const trimmedQuery = deferredQuery.trim();
  const summary = resultsSummary({ filter, query: deferredQuery, matches: visible.length, shown: shown.length, counts });
  const current = currentSelection(profiles, selectedId, session);
  const meta = publicListMeta({ info: publicListInfo(profiles, store.publicProxyRefresh), refreshing, failure: refreshFailure });
  const more = moreBlockCopy(shown.length, visible.length);

  // The bulk dialog follows live state while open and keeps its last copy for the exit animation.
  const bulkCopyRef = useRef<BulkRemoveCopy>();
  if (removal?.kind === "bulk" && removalOpen && !removing) {
    const sshName = activeTransport === "ssh" && runtime.state !== "Disconnected" && runtime.state !== "Error" ? activeTargetName(snapshot) : undefined;
    bulkCopyRef.current = bulkRemoveCopy({
      counts,
      session,
      sessionProfile: session?.profileId ? profiles.find((profile) => profile.id === session.profileId) : undefined,
      sshSessionName: sshName
    });
  }
  const xrayStillUp = activeTransport === "xray" && runtime.state !== "Disconnected" && runtime.state !== "Error";

  return (
    <>
      <PageHeader
        className="pf-topbar"
        eyebrow="Library"
        title="Xray profiles"
        sub="Your VLESS, VMess, Trojan and Hysteria 2 endpoints, stored securely on this device. Click a card to make it the profile Connect uses."
        actions={
          <>
            <Button icon={Upload} disabled={pageBusy} onClick={() => openImport()}>
              Import links
            </Button>
            <Button variant="primary" icon={Plus} disabled={pageBusy} onClick={() => setAddOpen(true)}>
              Add profile
            </Button>
          </>
        }
      />

      {libraryEmpty ? (
        <ProfilesOnboarding refreshing={refreshing} onAdd={() => setAddOpen(true)} onImport={() => openImport()} onRefresh={() => void refresh()} />
      ) : (
        <div className="pf-lib">
          <ProfilesToolbar
            query={query}
            onQueryChange={changeQuery}
            filter={filter}
            onFilterChange={setFilter}
            counts={counts}
            publicMeta={meta}
            refreshing={refreshing}
            busy={removing}
            onRefresh={() => void refresh()}
            onRemoveUnpinned={askRemoveUnpinned}
          />

          <div className="pf-resbar rise" style={{ "--d": 2 } as CSSProperties}>
            <div className="pf-res" aria-live="polite">
              <span className="pf-res-count">{summary.text}</span>
              <span className="pf-res-sub">{summary.sub}</span>
            </div>
            <div className="pf-current">
              <span className={cx("dot", !current.name && "is-none")} aria-hidden="true" />
              <span className="faint nowrap">{current.label}</span>
              {current.name ? (
                <span className="pf-current-name truncate" title={current.name}>
                  {current.name}
                </span>
              ) : null}
              <LinkButton className="nowrap" onClick={openConnect}>
                Open Connect
              </LinkButton>
            </div>
          </div>

          {filter === "gone" && visible.length > 0 && !trimmedQuery ? (
            <Callout tone="info" icon={Info} title="Review what dropped out of the public list" className="anim-swap">
              Gone profiles are never removed on their own. Pin the ones you still want, then use Remove unpinned to clear the rest.
            </Callout>
          ) : null}

          {shown.length > 0 ? (
            <div className="grid-auto pf-grid" key={`grid-${filter}`} ref={gridRef}>
              {shown.map((profile, index) => (
                <ProfileCard
                  key={profile.id}
                  profile={profile}
                  selected={profile.id === selectedId}
                  session={session}
                  index={index}
                  leaving={Boolean(exiting?.ids.has(profile.id))}
                  renameKeyHint={renameKeyHint}
                  onSelect={selectProfile}
                  onTogglePin={togglePin}
                  onRemove={askRemove}
                  onRename={renameProfile}
                  onCopyLink={copyLink}
                />
              ))}
            </div>
          ) : null}

          {visible.length === 0 && trimmedQuery ? (
            <EmptyState
              icon={Search}
              className="pf-empty anim-swap"
              title={<span className="break">{noMatchCopy(filter, trimmedQuery).title}</span>}
              action={
                <>
                  <Button size="sm" icon={X} onClick={() => changeQuery("")}>
                    Clear search
                  </Button>
                  {filter !== "all" ? (
                    <Button size="sm" variant="ghost" onClick={() => setFilter("all")}>
                      Search all profiles
                    </Button>
                  ) : null}
                </>
              }
            >
              {noMatchCopy(filter, trimmedQuery).text}
            </EmptyState>
          ) : null}

          {visible.length === 0 && !trimmedQuery && filter !== "all" ? (
            <EmptyState
              icon={Filter}
              className="pf-empty anim-swap"
              title={filterEmptyCopy(filter).title}
              action={
                <Button size="sm" onClick={() => setFilter("all")}>
                  Show all profiles
                </Button>
              }
            >
              {filterEmptyCopy(filter).text}
            </EmptyState>
          ) : null}

          {visible.length > shown.length ? (
            <div className="pf-more rise" style={{ "--d": 12 } as CSSProperties}>
              <div className="progress pf-more-bar" aria-hidden="true">
                <span style={{ width: `${more.percent}%` }} />
              </div>
              <span className="pf-more-meta">{more.meta}</span>
              <Button
                icon={ChevronDown}
                busy={morePending}
                onClick={() => {
                  focusCardAt.current = limit;
                  startMore(() => setPaging({ key: pageKey, count: nextRenderPageCount(limit, visible.length, PROFILE_PAGE_SIZE) }));
                }}
              >
                {more.label}
              </Button>
            </div>
          ) : null}
        </div>
      )}

      <AddProfileDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onOpenImport={(text) => {
          setAddOpen(false);
          openImport(text);
        }}
      />
      <ImportLinksDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        prefill={importPrefill}
        canRemoveUnpinned={counts.unpinned > 0 && !pageBusy}
        onRemoveUnpinned={() => {
          setImportOpen(false);
          askRemoveUnpinned();
        }}
      />
      <RemoveProfileDialog
        open={removalOpen && removal?.kind === "one"}
        profile={removal?.kind === "one" ? removal.profile : undefined}
        busy={removing}
        error={removeError}
        onConfirm={() => void confirmRemoval()}
        onCancel={closeRemoval}
      />
      <RemoveUnpinnedDialog
        open={removalOpen && removal?.kind === "bulk"}
        copy={bulkCopyRef.current}
        busyLabel={xrayStillUp ? "Stopping Xray…" : "Removing…"}
        busy={removing}
        error={removeError}
        onConfirm={() => void confirmRemoval()}
        onCancel={closeRemoval}
      />
      <span className="sr-only" aria-live="polite">
        <span key={renameNotice.seq}>{renameNotice.text}</span>
      </span>
    </>
  );
}
