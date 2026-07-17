import { Check, Download, Layers3, Pin, PinOff, Plus, RefreshCw, RotateCw, Search, ShieldAlert, SlidersHorizontal, Trash2, Waypoints, X } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import type { AppSnapshot, ImportProxyProfilesInput, ProxyProfile, UpsertProxyProfileInput } from "../../../shared/types.js";
import { checkButtonClass } from "../../lib/labels.js";
import type { ConfirmationRequest } from "../../lib/confirmation-controller.js";
import { nextRenderPageCount, sliceRenderPage } from "../../lib/render-page.js";
import { EmptyState, Modal } from "../ui/index.js";

const PROFILE_RENDER_PAGE_SIZE = 100;

export function XrayView({
  snapshot,
  busy,
  checking,
  selectedRulesBlocked,
  onConnect,
  onDisconnect,
  onCheckTunnel,
  onEditEndpoint,
  onRefresh,
  onUpsert,
  onImport,
  onSelect,
  onTogglePin,
  onDelete,
  onDeleteUnpinned,
  requestConfirmation,
  onAcceptRisk
}: {
  snapshot: AppSnapshot;
  busy: boolean;
  checking: boolean;
  selectedRulesBlocked: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onCheckTunnel: () => void;
  onEditEndpoint: () => void;
  onRefresh: () => Promise<void>;
  onUpsert: (input: UpsertProxyProfileInput) => Promise<void>;
  onImport: (input: ImportProxyProfilesInput) => Promise<void>;
  onSelect: (id: string) => Promise<void>;
  onTogglePin: (id: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onDeleteUnpinned: () => Promise<void>;
  requestConfirmation: (request: ConfirmationRequest) => boolean;
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
  const [manualSubmitting, setManualSubmitting] = useState(false);
  const [importSubmitting, setImportSubmitting] = useState(false);
  const profilePageKey = JSON.stringify([search, store.proxyProfiles.length]);
  const [profilePage, setProfilePage] = useState(() => ({ key: profilePageKey, count: PROFILE_RENDER_PAGE_SIZE }));

  const selectedProfile = store.proxyProfiles.find((profile) => profile.id === store.selectedProxyProfileId);
  const xrayState = runtime.transport === "xray" ? runtime.state : "Disconnected";
  const connected = xrayState === "Connected" || xrayState === "Connecting" || xrayState === "Reconnecting";
  const connectionMarkClass = xrayState === "Connected"
    ? "connection-mark active"
    : xrayState === "Connecting" || xrayState === "Reconnecting" || xrayState === "Disconnecting"
      ? "connection-mark pending"
      : "connection-mark";
  const unsupportedReason = selectedProfile ? unsupportedProfileReason(selectedProfile) : "";
  const filteredProfiles = useMemo(() => {
    const query = search.trim().toLowerCase();
    return store.proxyProfiles.filter((profile) =>
      query
        ? `${profile.name} ${profile.protocol} ${profile.host} ${profile.transport} ${profile.security}`.toLowerCase().includes(query)
        : true
    );
  }, [search, store.proxyProfiles]);
  const visibleProfileCount = profilePage.key === profilePageKey ? profilePage.count : PROFILE_RENDER_PAGE_SIZE;
  const visibleProfiles = sliceRenderPage(filteredProfiles, visibleProfileCount);

  useEffect(() => {
    setProfilePage((current) => current.key === profilePageKey
      ? current
      : { key: profilePageKey, count: PROFILE_RENDER_PAGE_SIZE });
  }, [profilePageKey]);

  async function submitManual(event: FormEvent): Promise<void> {
    event.preventDefault();
    setLocalError("");
    setManualSubmitting(true);
    try {
      await onUpsert({ name: profileName, rawUri, source: "manual" });
      setProfileName("");
      setRawUri("");
      setManualOpen(false);
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error));
    } finally {
      setManualSubmitting(false);
    }
  }

  async function submitImport(event: FormEvent): Promise<void> {
    event.preventDefault();
    setLocalError("");
    setImportSubmitting(true);
    try {
      await onImport({ text: importText, source: "clipboard" });
      setImportText("");
      setImportOpen(false);
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error));
    } finally {
      setImportSubmitting(false);
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

        <div className="connection-summary">
          <div className={connectionMarkClass} aria-hidden="true">
            <Waypoints size={21} />
          </div>
          <div className="connection-copy">
            <span className="connection-label">{xrayState}</span>
            <strong>{selectedProfile?.name ?? "Ready for a proxy profile"}</strong>
            <span>{selectedProfile ? `${selectedProfile.protocol.toUpperCase()} · ${selectedProfile.host}:${selectedProfile.port}` : "Select or import a profile to begin"}</span>
          </div>
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

        <div className="field endpoint-summary">
          <span>Check tunnel endpoint</span>
          <div className="endpoint-line">
            <strong>{store.settings.checkEndpoint}</strong>
            <button type="button" className="ghost-button" onClick={onEditEndpoint}>
              <SlidersHorizontal size={16} /> Edit
            </button>
          </div>
        </div>

        <dl className="facts single-facts">
          <div><dt>Routing mode</dt><dd>{store.routingMode === "proxy-all" ? "Proxy all" : "Selected rules"}</dd></div>
        </dl>
      </section>

      <section className="panel settings-wide">
        <div className="section-title">
          <div className="panel-heading">
            <span className="panel-heading-icon" aria-hidden="true"><Layers3 size={18} /></span>
            <div className="panel-heading-copy">
              <h2>Profiles</h2>
              <p>Private proxy endpoints stored securely on this device</p>
            </div>
          </div>
          <span className="count-badge">{store.proxyProfiles.length} total</span>
        </div>
        <div className="toolbar">
          <button type="button" className="primary-button" disabled={busy} onClick={() => setManualOpen(true)}>
            <Plus size={18} /> Add profile
          </button>
          <button type="button" className="ghost-button" disabled={busy} onClick={() => setImportOpen(true)}>
            <Download size={18} /> Import links
          </button>
          <button type="button" className="ghost-button" disabled={busy} onClick={() => void onRefresh().catch(() => undefined)}>
            <RotateCw size={18} /> Refresh public configs
          </button>
          <button
            type="button"
            className="ghost-button"
            disabled={busy || store.proxyProfiles.every((profile) => profile.isPinned)}
            onClick={() => {
              requestConfirmation({
                title: "Delete unpinned Xray profiles",
                message: "Delete all unpinned Xray profiles?",
                confirmLabel: "Delete",
                pendingLabel: "Deleting...",
                onConfirm: onDeleteUnpinned
              });
            }}
          >
            <Trash2 size={18} /> Delete unpinned
          </button>
          <label className="search-box">
            <Search size={16} aria-hidden="true" />
            <input aria-label="Search Xray profiles" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search profiles" />
          </label>
        </div>

        {filteredProfiles.length === 0 ? (
          <EmptyState text="No Xray profiles found." />
        ) : (
          <>
            <div className="profile-grid">
              {visibleProfiles.map((profile) => (
                <article key={profile.id} className={`profile-card${profile.id === store.selectedProxyProfileId ? " selected" : ""}`}>
                <button
                  type="button"
                  className="profile-select"
                  aria-pressed={profile.id === store.selectedProxyProfileId}
                  aria-label={`Select Xray profile ${profile.name}`}
                  onClick={() => void onSelect(profile.id)}
                >
                  <strong>{profile.name}</strong>
                  <span>{profile.protocol.toUpperCase()} · {profile.host}:{profile.port}</span>
                  <small>{profile.transport} · {profile.security}{profile.isStale ? " · stale" : ""}</small>
                </button>
                <div className="item-actions">
                  <button type="button" className="icon-button" onClick={() => void onTogglePin(profile.id)} aria-label={`${profile.isPinned ? "Unpin" : "Pin"} profile ${profile.name}`}>
                    {profile.isPinned ? <PinOff size={16} /> : <Pin size={16} />}
                  </button>
                  <button
                    type="button"
                    className="icon-button danger"
                    disabled={connected && runtime.activeConfigId === profile.id}
                    onClick={() => {
                      requestConfirmation({
                        title: "Delete Xray profile",
                        message: `Delete profile "${profile.name}"?`,
                        confirmLabel: "Delete",
                        pendingLabel: "Deleting...",
                        onConfirm: () => onDelete(profile.id)
                      });
                    }}
                    aria-label={`Delete profile ${profile.name}`}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
                </article>
              ))}
            </div>
            {visibleProfiles.length < filteredProfiles.length && (
              <div className="button-row">
                <button
                  type="button"
                  className="ghost-button"
                  onClick={() => setProfilePage({
                    key: profilePageKey,
                    count: nextRenderPageCount(visibleProfileCount, filteredProfiles.length, PROFILE_RENDER_PAGE_SIZE)
                  })}
                >
                  Show more ({filteredProfiles.length - visibleProfiles.length} remaining)
                </button>
              </div>
            )}
          </>
        )}
      </section>

      <Modal open={manualOpen} title="Add Xray profile" onClose={() => setManualOpen(false)} closeDisabled={manualSubmitting}>
        <form className="modal-form" aria-busy={manualSubmitting} onSubmit={(event) => void submitManual(event)}>
          {localError && <div className="inline-error modal-error" role="alert">{localError}</div>}
          <fieldset className="modal-fieldset" disabled={manualSubmitting}>
            <label className="field">
              <span>Name</span>
              <input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder="Optional profile name" />
            </label>
            <label className="field">
              <span>VLESS, VMess, or Trojan link</span>
              <textarea className="secret-textarea" value={rawUri} onChange={(event) => setRawUri(event.target.value)} placeholder="vless://..., vmess://..., trojan://..." />
            </label>
            <div className="modal-actions">
              <button type="button" className="ghost-button" disabled={manualSubmitting} onClick={() => setManualOpen(false)}>Cancel</button>
              <button type="submit" className="primary-button" disabled={manualSubmitting || !rawUri.trim()}>{manualSubmitting ? "Saving…" : "Save profile"}</button>
            </div>
          </fieldset>
        </form>
      </Modal>

      <Modal open={importOpen} title="Import Xray links" onClose={() => setImportOpen(false)} closeDisabled={importSubmitting}>
        <form className="modal-form" aria-busy={importSubmitting} onSubmit={(event) => void submitImport(event)}>
          {localError && <div className="inline-error modal-error" role="alert">{localError}</div>}
          <fieldset className="modal-fieldset" disabled={importSubmitting}>
            <label className="field">
              <span>Links</span>
              <textarea className="secret-textarea" value={importText} onChange={(event) => setImportText(event.target.value)} placeholder="Paste one share link per line" />
            </label>
            <div className="modal-actions">
              <button type="button" className="ghost-button" disabled={importSubmitting} onClick={() => setImportOpen(false)}>Cancel</button>
              <button type="submit" className="primary-button" disabled={importSubmitting || !importText.trim()}>{importSubmitting ? "Importing…" : "Import"}</button>
            </div>
          </fieldset>
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
