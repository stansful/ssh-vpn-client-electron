import { Check, Download, Pin, PinOff, Plus, RefreshCw, RotateCw, ShieldAlert, Trash2, X } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import type { AppSnapshot, ImportProxyProfilesInput, ProxyProfile, UpsertProxyProfileInput } from "../../../shared/types.js";
import { checkButtonClass } from "../../lib/labels.js";
import { Modal } from "../ui/index.js";

export function XrayView({
  snapshot,
  busy,
  checking,
  selectedRulesBlocked,
  onConnect,
  onDisconnect,
  onCheckTunnel,
  onRefresh,
  onUpsert,
  onImport,
  onSelect,
  onTogglePin,
  onDelete,
  onDeleteUnpinned,
  onAcceptRisk
}: {
  snapshot: AppSnapshot;
  busy: boolean;
  checking: boolean;
  selectedRulesBlocked: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onCheckTunnel: () => void;
  onRefresh: () => Promise<void>;
  onUpsert: (input: UpsertProxyProfileInput) => Promise<void>;
  onImport: (input: ImportProxyProfilesInput) => Promise<void>;
  onSelect: (id: string) => Promise<void>;
  onTogglePin: (id: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onDeleteUnpinned: () => Promise<void>;
  onAcceptRisk: () => void;
}): JSX.Element {
  const { store, runtime, lastTunnelCheck } = snapshot;
  const [manualOpen, setManualOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [profileName, setProfileName] = useState("");
  const [rawUri, setRawUri] = useState("");
  const [importText, setImportText] = useState("");
  const [localError, setLocalError] = useState("");
  const [search, setSearch] = useState("");

  const selectedProfile = store.proxyProfiles.find((profile) => profile.id === store.selectedProxyProfileId);
  const connected = runtime.transport === "xray" && (runtime.state === "Connected" || runtime.state === "Connecting" || runtime.state === "Reconnecting");
  const unsupportedReason = selectedProfile ? unsupportedProfileReason(selectedProfile) : "";
  const filteredProfiles = useMemo(() => {
    const query = search.trim().toLowerCase();
    return store.proxyProfiles.filter((profile) =>
      query
        ? `${profile.name} ${profile.protocol} ${profile.host} ${profile.transport} ${profile.security}`.toLowerCase().includes(query)
        : true
    );
  }, [search, store.proxyProfiles]);

  async function submitManual(event: FormEvent): Promise<void> {
    event.preventDefault();
    setLocalError("");
    try {
      await onUpsert({ name: profileName, rawUri, source: "manual" });
      setProfileName("");
      setRawUri("");
      setManualOpen(false);
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error));
    }
  }

  async function submitImport(event: FormEvent): Promise<void> {
    event.preventDefault();
    setLocalError("");
    try {
      await onImport({ text: importText, source: "clipboard" });
      setImportText("");
      setImportOpen(false);
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error));
    }
  }

  return (
    <section className="screen xray-screen">
      {store.settings.xrayRiskBannerExpanded && (
        <section className="panel risk-panel">
          <div>
            <h2><ShieldAlert size={18} /> Xray transport</h2>
            <p>VLESS, VMess, and Trojan profiles run through the bundled Xray runtime. Use profiles only from sources you trust.</p>
          </div>
          <button type="button" className="ghost-button" onClick={onAcceptRisk}>
            <Check size={16} /> I understand
          </button>
        </section>
      )}

      <section className="panel">
        <div className="section-title">
          <h2>Connection</h2>
          <span>{selectedProfile ? `${selectedProfile.protocol.toUpperCase()} ${selectedProfile.host}:${selectedProfile.port}` : "No profile selected"}</span>
        </div>

        {selectedRulesBlocked && (
          <div className="warning-row">
            Selected rules mode requires at least one enabled rule before Connect.
          </div>
        )}
        {unsupportedReason && (
          <div className="warning-row">
            {unsupportedReason}
          </div>
        )}

        <div className="button-row">
          {connected ? (
            <button className="danger-button" type="button" disabled={busy} onClick={onDisconnect}>
              <X size={18} /> Disconnect
            </button>
          ) : (
            <button
              className="primary-button"
              type="button"
              disabled={busy || !selectedProfile || selectedRulesBlocked || Boolean(unsupportedReason)}
              onClick={onConnect}
            >
              <Check size={18} /> Connect
            </button>
          )}
          <button
            className={checkButtonClass(lastTunnelCheck?.ok, checking)}
            type="button"
            disabled={checking || runtime.state !== "Connected" || runtime.transport !== "xray"}
            onClick={onCheckTunnel}
          >
            {checking ? <RefreshCw className="spin" size={18} /> : lastTunnelCheck?.ok ? <Check size={18} /> : lastTunnelCheck ? <X size={18} /> : <RefreshCw size={18} />}
            Check tunnel
          </button>
        </div>

        <dl className="facts">
          <div><dt>Routing mode</dt><dd>{store.routingMode === "proxy-all" ? "Proxy all" : "Selected rules"}</dd></div>
          <div><dt>Profiles</dt><dd>{store.proxyProfiles.length}</dd></div>
          <div><dt>Pinned</dt><dd>{store.proxyProfiles.filter((profile) => profile.isPinned).length}</dd></div>
          <div><dt>Endpoint</dt><dd>{store.settings.checkEndpoint}</dd></div>
        </dl>
      </section>

      <section className="panel settings-wide">
        <div className="section-title">
          <h2>Profiles</h2>
          <span>Manual refresh only</span>
        </div>
        <div className="toolbar">
          <button type="button" className="primary-button" disabled={busy} onClick={() => setManualOpen(true)}>
            <Plus size={18} /> Add profile
          </button>
          <button type="button" className="ghost-button" disabled={busy} onClick={() => setImportOpen(true)}>
            <Download size={18} /> Import links
          </button>
          <button type="button" className="ghost-button" disabled={busy} onClick={() => void onRefresh()}>
            <RotateCw size={18} /> Refresh public configs
          </button>
          <button
            type="button"
            className="ghost-button"
            disabled={busy || store.proxyProfiles.every((profile) => profile.isPinned)}
            onClick={() => {
              if (window.confirm("Delete all unpinned Xray profiles?")) {
                void onDeleteUnpinned();
              }
            }}
          >
            <Trash2 size={18} /> Delete unpinned
          </button>
          <label className="search-box">
            <span>Search</span>
            <input value={search} onChange={(event) => setSearch(event.target.value)} />
          </label>
        </div>

        {filteredProfiles.length === 0 ? (
          <div className="empty-state">No Xray profiles found.</div>
        ) : (
          <div className="profile-grid">
            {filteredProfiles.map((profile) => (
              <article key={profile.id} className={`profile-card${profile.id === store.selectedProxyProfileId ? " selected" : ""}`}>
                <button type="button" className="profile-select" onClick={() => void onSelect(profile.id)}>
                  <strong>{profile.name}</strong>
                  <span>{profile.protocol.toUpperCase()} · {profile.host}:{profile.port}</span>
                  <small>{profile.transport} · {profile.security}{profile.isStale ? " · stale" : ""}</small>
                </button>
                <div className="item-actions">
                  <button type="button" className="icon-button" onClick={() => void onTogglePin(profile.id)} aria-label={profile.isPinned ? "Unpin profile" : "Pin profile"}>
                    {profile.isPinned ? <PinOff size={16} /> : <Pin size={16} />}
                  </button>
                  <button
                    type="button"
                    className="icon-button danger"
                    disabled={connected && runtime.activeConfigId === profile.id}
                    onClick={() => {
                      if (window.confirm(`Delete profile "${profile.name}"?`)) {
                        void onDelete(profile.id);
                      }
                    }}
                    aria-label="Delete profile"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <Modal open={manualOpen} title="Add Xray profile" onClose={() => setManualOpen(false)}>
        <form className="modal-form" onSubmit={(event) => void submitManual(event)}>
          {localError && <div className="inline-error modal-error">{localError}</div>}
          <label className="field">
            <span>Name</span>
            <input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder="Optional profile name" />
          </label>
          <label className="field">
            <span>VLESS, VMess, or Trojan link</span>
            <textarea className="secret-textarea" value={rawUri} onChange={(event) => setRawUri(event.target.value)} placeholder="vless://..., vmess://..., trojan://..." />
          </label>
          <div className="modal-actions">
            <button type="button" className="ghost-button" onClick={() => setManualOpen(false)}>Cancel</button>
            <button type="submit" className="primary-button" disabled={busy || !rawUri.trim()}>Save profile</button>
          </div>
        </form>
      </Modal>

      <Modal open={importOpen} title="Import Xray links" onClose={() => setImportOpen(false)}>
        <form className="modal-form" onSubmit={(event) => void submitImport(event)}>
          {localError && <div className="inline-error modal-error">{localError}</div>}
          <label className="field">
            <span>Links</span>
            <textarea className="secret-textarea" value={importText} onChange={(event) => setImportText(event.target.value)} placeholder="Paste one share link per line" />
          </label>
          <div className="modal-actions">
            <button type="button" className="ghost-button" onClick={() => setImportOpen(false)}>Cancel</button>
            <button type="submit" className="primary-button" disabled={busy || !importText.trim()}>Import</button>
          </div>
        </form>
      </Modal>
    </section>
  );
}

function unsupportedProfileReason(profile: ProxyProfile): string {
  if (profile.security === "unknown") {
    return "This profile uses an unsupported security mode.";
  }
  if (profile.transport === "unknown") {
    return "This profile uses an unsupported or unrecognized Xray transport.";
  }
  return "";
}
