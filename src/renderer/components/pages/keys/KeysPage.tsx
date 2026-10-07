import { Check, Clock, Info, KeyRound, Plus, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { useNavigation } from "../../../hooks/useNavigation.js";
import type { NavigationIntent, PageProps } from "../../../types.js";
import { PageHeader } from "../../shell/index.js";
import { Badge, Button, Icon } from "../../ui/index.js";
import { useExitingItems } from "../servers/exiting-items.js";
import { KeyCard } from "./KeyCard.js";
import { KeyFormModal, nextFormToken, type KeyFormRequest } from "./KeyFormModal.js";
import { KeyInUseDialog, type KeyInUse } from "./KeyInUseDialog.js";
import { keyDeleteDescription, keyDeletedMessage, keyTypeLabel, serversUsingKey, shortKeyId } from "./key-model.js";
import { rememberKeyForServerForm } from "./pending-key.js";
import type { SshKeyMetadata } from "../../../../shared/types.js";

const CARD_EXIT_MS = 380;
const NUDGE_MS = 1800;

const keyId = (key: SshKeyMetadata): string => key.id;

export function KeysPage({ intent }: PageProps): JSX.Element {
  const { store, run, toast, confirm, navigate } = useAppData();
  const { clearIntent } = useNavigation();
  const [form, setForm] = useState<KeyFormRequest | null>(null);
  const [inUse, setInUse] = useState<KeyInUse | null>(null);
  const [nudges, setNudges] = useState<Record<string, number>>({});
  const nudgeTimers = useRef(new Map<string, number>());
  const { entries, markLeaving } = useExitingItems(store.sshKeys, keyId, CARD_EXIT_MS);

  const keys = store.sshKeys;
  const total = keys.length;
  const inUseCount = keys.filter((key) => serversUsingKey(store.sshConfigs, key.id).length > 0).length;

  useEffect(() => {
    const timers = nudgeTimers.current;
    return () => {
      for (const timer of timers.values()) {
        window.clearTimeout(timer);
      }
    };
  }, []);

  const openForm = useCallback((next: Omit<KeyFormRequest, "token">): void => {
    setForm({ ...next, token: nextFormToken() });
  }, []);

  // StrictMode replays effects; an intent is acted on once.
  const handledIntent = useRef<NavigationIntent>();
  useEffect(() => {
    if (!intent || intent === handledIntent.current) {
      return;
    }
    handledIntent.current = intent;
    if (intent.type === "new-key") {
      openForm({ mode: "create", opensNewServer: intent.returnTo === "server-form" });
      clearIntent();
    } else if (intent.type === "edit-key") {
      if (store.sshKeys.some((key) => key.id === intent.id)) {
        openForm({ mode: "edit", keyId: intent.id });
      } else {
        toast({ tone: "info", title: "That key is no longer saved", message: "It was deleted, so there is nothing to edit." });
      }
      clearIntent();
    }
    // Act once per navigation; the store is read at that moment.
  }, [intent]);

  const nudge = (id: string): void => {
    setNudges((current) => ({ ...current, [id]: (current[id] ?? 0) + 1 }));
    window.clearTimeout(nudgeTimers.current.get(id));
    nudgeTimers.current.set(
      id,
      window.setTimeout(() => {
        nudgeTimers.current.delete(id);
        setNudges((current) => ({ ...current, [id]: 0 }));
      }, NUDGE_MS)
    );
  };

  const requestDelete = (key: SshKeyMetadata): void => {
    const users = serversUsingKey(store.sshConfigs, key.id);
    if (users.length > 0) {
      nudge(key.id);
      setInUse({ key, users });
      return;
    }
    void confirm({
      eyebrow: "SSH keys",
      title: `Delete ${key.name}?`,
      description: keyDeleteDescription(key),
      body: (
        <>
          <div className="ky-target">
            <span className="icon-tile" aria-hidden="true">
              <Icon icon={KeyRound} />
            </span>
            <div className="ky-target-main">
              <span className="ky-target-name">{key.name}</span>
              <span className="ky-target-id">Key ID {shortKeyId(key.fingerprint)}</span>
            </div>
            <Badge tone="outline" square>
              {keyTypeLabel(key.keyType)}
            </Badge>
          </div>
          <p className="ky-safe">
            <Icon icon={Check} />
            No server signs in with this key, so nothing else changes.
          </p>
        </>
      ),
      confirmLabel: "Delete key",
      busyLabel: "Deleting…",
      errorTitle: "Couldn't delete the key",
      onConfirm: async () => {
        markLeaving(key.id);
        await run(() => api.deleteKey(key.id), { silent: true, rethrow: true });
        toast({ tone: "success", title: "Key deleted", message: keyDeletedMessage(key) });
      }
    });
  };

  return (
    <>
      <PageHeader
        eyebrow="Library"
        title="SSH keys"
        sub="Private keys your servers sign in with. They’re encrypted by your system keychain and stored only on this device."
        actions={
          <Button variant="primary" icon={Plus} onClick={() => openForm({ mode: "create" })}>
            Add key
          </Button>
        }
      />

      {total > 0 || entries.length > 0 ? (
        <section className="ky-block" aria-label="Saved keys">
          <div className="ky-listhead rise" style={{ "--d": 1 } as CSSProperties}>
            <h2 className="ky-total">
              <b>{total}</b>
              <span>{total === 1 ? "key" : "keys"}</span>
              <span>· {inUseCount} in use</span>
            </h2>
            <span className="ky-note">
              <Icon icon={Clock} />
              Changes apply the next time you connect.
            </span>
          </div>

          <div className="ky-grid" role="list" aria-label="SSH keys">
            {entries.map((entry, index) => (
              <KeyCard
                key={entry.item.id}
                sshKey={entry.item}
                users={serversUsingKey(store.sshConfigs, entry.item.id)}
                index={index}
                leaving={entry.leaving}
                nudge={nudges[entry.item.id] ?? 0}
                onEdit={() => openForm({ mode: "edit", keyId: entry.item.id })}
                onDelete={() => requestDelete(entry.item)}
                onOpenServers={() => navigate("servers")}
              />
            ))}
          </div>
        </section>
      ) : (
        <div className="empty ky-empty rise" style={{ "--d": 1 } as CSSProperties}>
          <span className="empty-icon">
            <Icon icon={KeyRound} size="xl" />
          </span>
          <span className="eyebrow">Nothing here yet</span>
          <span className="empty-title">Add your first SSH key</span>
          <p>Paste a private key once, then pick it for any server that signs in with a key. It’s encrypted before it’s saved.</p>
          <Button variant="primary" icon={Plus} onClick={() => openForm({ mode: "create" })}>
            Add key
          </Button>
        </div>
      )}

      <section className="callout t-info rise" style={{ "--d": 6 } as CSSProperties} aria-labelledby="ky-sup-title">
        <Icon icon={Info} />
        <div className="callout-body">
          <span className="callout-title" id="ky-sup-title">
            Which keys work
          </span>
          <span className="ky-sup-lead">
            Paste the key text itself. A key is fully checked only when you connect, so an unsupported one saves without an error and fails at sign-in.
          </span>
          <div className="ky-sup">
            <div className="ky-sup-col">
              <span className="eyebrow">Supported</span>
              <ul>
                <li className="is-yes">
                  <Icon icon={Check} />
                  <span>RSA and Ed25519 keys</span>
                </li>
                <li className="is-yes">
                  <Icon icon={Check} />
                  <span>OpenSSH and PEM formats</span>
                </li>
                <li className="is-yes">
                  <Icon icon={Check} />
                  <span>Passphrases on PEM and PKCS#8 keys</span>
                </li>
              </ul>
            </div>
            <div className="ky-sup-col">
              <span className="eyebrow">Not supported yet</span>
              <ul>
                <li className="is-no">
                  <Icon icon={X} />
                  <span>Passphrase-protected OpenSSH keys</span>
                </li>
                <li className="is-no">
                  <Icon icon={X} />
                  <span>ECDSA and DSA keys</span>
                </li>
                <li className="is-no">
                  <Icon icon={X} />
                  <span>Key files and PuTTY .ppk — paste the text instead</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <KeyFormModal
        request={form}
        onClose={() => setForm(null)}
        onSaved={(savedId) => {
          if (form?.opensNewServer) {
            rememberKeyForServerForm(savedId);
            navigate("servers", { type: "new-server" });
          }
        }}
      />
      <KeyInUseDialog
        value={inUse}
        onClose={() => setInUse(null)}
        onEditServer={(configId) => {
          setInUse(null);
          navigate("servers", { type: "edit-server", id: configId });
        }}
      />
    </>
  );
}
