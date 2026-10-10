import { ArrowRight, BadgeCheck, Clock, KeyRound, Plus, Search, Server } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { useNavigation } from "../../../hooks/useNavigation.js";
import { initials } from "../../../lib/format.js";
import type { NavigationIntent, PageProps } from "../../../types.js";
import { PageHeader } from "../../shell/index.js";
import { Button, Callout, Icon, IconTile, SearchInput } from "../../ui/index.js";
import { nextFormToken } from "../keys/KeyFormModal.js";
import { takeKeyForServerForm } from "../keys/pending-key.js";
import { useExitingItems } from "./exiting-items.js";
import { ServerFormModal, type ServerFormRequest } from "./ServerFormModal.js";
import { LiveBadge, ServerRow } from "./ServerRow.js";
import {
  filterServers,
  liveDeletedCallout,
  matchLabel,
  serverAddress,
  serverCountWord,
  serverDeleteCopy,
  serverDeletedMessage,
  sshSessionView,
  upNextCallout
} from "./server-model.js";
import type { SshConfig } from "../../../../shared/types.js";

const ROW_EXIT_MS = 420;

const configId = (config: SshConfig): string => config.id;

export function ServersPage({ intent }: PageProps): JSX.Element {
  const { snapshot, store, run, toast, confirm, navigate } = useAppData();
  const { clearIntent } = useNavigation();
  const [query, setQuery] = useState("");
  const [form, setForm] = useState<ServerFormRequest | null>(null);
  const [justSelected, setJustSelected] = useState<string>();
  const { entries, markLeaving } = useExitingItems(store.sshConfigs, configId, ROW_EXIT_MS);

  const session = sshSessionView(snapshot);
  const configs = store.sshConfigs;
  const selectedId = store.selectedConfigId;
  const total = configs.length;
  const trimmedQuery = query.trim();

  const openForm = useCallback((next: Omit<ServerFormRequest, "token">): void => {
    setForm({ ...next, token: nextFormToken() });
  }, []);

  // StrictMode replays effects; an intent is acted on once.
  const handledIntent = useRef<NavigationIntent>();
  useEffect(() => {
    if (!intent || intent === handledIntent.current) {
      return;
    }
    handledIntent.current = intent;
    if (intent.type === "new-server") {
      openForm({ mode: "create", presetKeyId: takeKeyForServerForm() });
      clearIntent();
    } else if (intent.type === "edit-server") {
      if (store.sshConfigs.some((config) => config.id === intent.id)) {
        openForm({ mode: "edit", configId: intent.id });
      } else {
        toast({ tone: "info", title: "That server is no longer saved", message: "It was deleted, so there is nothing to edit." });
      }
      clearIntent();
    }
    // Act once per navigation; the store is read at that moment.
  }, [intent]);

  useEffect(() => {
    if (total === 0) {
      setQuery("");
    }
  }, [total]);

  const visible = useMemo(() => {
    const matching = new Set(filterServers(entries.map((entry) => entry.item), query).map(configId));
    return entries.filter((entry) => matching.has(entry.item.id));
  }, [entries, query]);
  const matchCount = visible.filter((entry) => !entry.leaving).length;

  const liveDeleted = liveDeletedCallout(configs, selectedId, session);
  const upNext = liveDeleted ? undefined : upNextCallout(configs, selectedId, session);

  const pickForConnect = (config: SshConfig): void => {
    setJustSelected(config.id);
    void run(() => api.selectConfig(config.id), { errorTitle: "Couldn't change the server Connect uses" });
  };

  const requestDelete = (config: SshConfig): void => {
    const copy = serverDeleteCopy(config, { configs, keys: store.sshKeys, selectedId, session });
    const liveState = copy.live ? session.state : undefined;
    void confirm({
      eyebrow: "SSH servers",
      title: copy.title,
      description: copy.description,
      body: (
        <>
          <div className="sv-target">
            <span className="sv-ava" aria-hidden="true">
              {initials(config.name)}
            </span>
            <div className="sv-main">
              <span className="sv-name">{config.name}</span>
              <span className="sv-addr">{serverAddress(config)}</span>
            </div>
            <LiveBadge state={liveState} className="sv-target-badge" />
          </div>
          {copy.live ? (
            <Callout tone="warn" title="It’s connected right now">
              Deleting won’t disconnect you. The session keeps running until you disconnect — after that, this server is gone.
            </Callout>
          ) : null}
          {copy.nextLine ? (
            <p className="sv-nextline">
              <Icon icon={ArrowRight} />
              {copy.nextLine}
            </p>
          ) : null}
        </>
      ),
      confirmLabel: "Delete server",
      busyLabel: "Deleting…",
      errorTitle: "Couldn't delete the server",
      onConfirm: async () => {
        markLeaving(config.id);
        await run(() => api.deleteConfig(config.id), { silent: true, rethrow: true });
        toast({ tone: "success", title: "Server deleted", message: serverDeletedMessage(config, { keys: store.sshKeys, wasLive: copy.live }) });
      }
    });
  };

  return (
    <>
      <PageHeader
        eyebrow="Library"
        title="SSH servers"
        sub="Where your SSH tunnel can go. Connect always uses the server marked “Used by Connect”."
        actions={
          <>
            {total > 0 ? (
              <div className="sv-search" role="search">
                <SearchInput value={query} onValueChange={setQuery} placeholder="Search servers" aria-label="Search servers" autoComplete="off" />
              </div>
            ) : null}
            <Button variant="primary" icon={Plus} onClick={() => openForm({ mode: "create" })}>
              Add server
            </Button>
          </>
        }
      />

      {liveDeleted ? (
        <Callout
          tone="warn"
          role="status"
          className="rise"
          title={liveDeleted.title}
          actions={
            <Button size="sm" onClick={() => navigate("connect")}>
              Open Connect
            </Button>
          }
        >
          {liveDeleted.message}
        </Callout>
      ) : null}

      {upNext ? (
        <Callout
          tone="info"
          role="status"
          className="rise"
          title={upNext.title}
          actions={
            <Button size="sm" onClick={() => navigate("connect")}>
              Open Connect
            </Button>
          }
        >
          {upNext.message}
        </Callout>
      ) : null}

      {total > 0 || entries.length > 0 ? (
        <section className="sv-block" aria-label="Saved servers">
          <div className="sv-listhead rise" style={{ "--d": 1 } as CSSProperties} aria-live="polite">
            <h2 className="sv-total">
              <b>{total}</b>
              <span>{serverCountWord(total)}</span>
              {trimmedQuery ? <span className="sv-match">· {matchLabel(matchCount)}</span> : null}
            </h2>
            <span className="sv-note">
              <Icon icon={Clock} />
              Changes apply the next time you connect.
            </span>
          </div>

          <div className="sv-list" role="list" aria-label="SSH servers">
            {visible.map((entry, index) => {
              const config = entry.item;
              return (
                <ServerRow
                  key={config.id}
                  config={config}
                  keys={store.sshKeys}
                  index={index}
                  selected={config.id === selectedId && !entry.leaving}
                  live={session.on && session.activeId === config.id ? session.state : undefined}
                  sessionOn={session.on}
                  leaving={entry.leaving}
                  focusWhenSelected={justSelected === config.id}
                  onUse={() => pickForConnect(config)}
                  onEdit={(focus) => openForm({ mode: "edit", configId: config.id, focus })}
                  onDelete={() => requestDelete(config)}
                  onOpenKeys={() => navigate("keys")}
                />
              );
            })}
          </div>

          {trimmedQuery && matchCount === 0 ? (
            <div className="empty anim-swap" role="status">
              <span className="empty-icon">
                <Icon icon={Search} size="lg" />
              </span>
              <span className="empty-title">No servers match “{trimmedQuery}”</span>
              <p>Search looks at server names, hosts and usernames.</p>
              <Button size="sm" onClick={() => setQuery("")}>
                Clear search
              </Button>
            </div>
          ) : null}
        </section>
      ) : (
        <div className="empty sv-empty rise" style={{ "--d": 1 } as CSSProperties}>
          <span className="empty-icon">
            <Icon icon={Server} size="xl" />
          </span>
          <span className="eyebrow">Nothing here yet</span>
          <span className="empty-title">Add your first SSH server</span>
          <p>Save the address and sign-in once, then connect with one tap. Passwords and keys stay encrypted on this device.</p>
          <div className="sv-empty-actions">
            <Button variant="primary" icon={Plus} onClick={() => openForm({ mode: "create" })}>
              Add server
            </Button>
            <Button variant="ghost" icon={KeyRound} onClick={() => navigate("keys", { type: "new-key" })}>
              Add an SSH key
            </Button>
          </div>
        </div>
      )}

      <div className="sv-tips rise" style={{ "--d": 8 } as CSSProperties}>
        <section className="sv-tip" aria-labelledby="sv-tip-pin">
          <IconTile icon={BadgeCheck} tone="ok" />
          <div className="sv-tip-copy">
            <h3 className="sv-tip-title" id="sv-tip-pin">
              Pin the host key
            </h3>
            <p>
              Paste the server’s SHA256 fingerprint when you edit it. Shadow then refuses to connect if that key ever changes, and can fall back to the
              last working address when DNS fails after sleep.
            </p>
            <code className="sv-code">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>
            <span className="hint">Run it on the server and copy the part that starts with SHA256:</span>
          </div>
        </section>
        <section className="sv-tip" aria-labelledby="sv-tip-key">
          <IconTile icon={KeyRound} tone="busy" />
          <div className="sv-tip-copy">
            <h3 className="sv-tip-title" id="sv-tip-key">
              Sign in with a key
            </h3>
            <p>Save a private key once in SSH keys, then pick it when you add or edit a server. One key can serve many servers.</p>
            <button type="button" className="link-btn" onClick={() => navigate("keys")}>
              Open SSH keys
              <Icon icon={ArrowRight} />
            </button>
          </div>
        </section>
      </div>

      <ServerFormModal request={form} onClose={() => setForm(null)} />
    </>
  );
}
