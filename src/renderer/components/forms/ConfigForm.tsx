import { Save } from "lucide-react";
import type { FormEvent } from "react";
import type { AuthType, SshKeyMetadata } from "../../../shared/types.js";
import type { ConfigDraft } from "../../types.js";
import { Field } from "../ui/index.js";
import { SecretField } from "./SecretField.js";

export function ConfigForm({
  draft,
  error,
  keys,
  onChange,
  onSubmit,
  onCancel
}: {
  draft: ConfigDraft;
  error: string;
  keys: SshKeyMetadata[];
  onChange: (draft: ConfigDraft) => void;
  onSubmit: (event: FormEvent) => void;
  onCancel: () => void;
}): JSX.Element {
  const set = <K extends keyof ConfigDraft>(key: K, value: ConfigDraft[K]): void => onChange({ ...draft, [key]: value });
  return (
    <form className="modal-form" onSubmit={onSubmit}>
      {error && <div className="inline-error modal-error">{error}</div>}
      <div className="form-grid">
        <Field label="Name"><input required value={draft.name} onChange={(event) => set("name", event.target.value)} /></Field>
        <Field label="Host"><input required value={draft.host} onChange={(event) => set("host", event.target.value)} /></Field>
        <Field label="Port"><input required type="number" min={1} max={65535} value={draft.port} onChange={(event) => set("port", Number(event.target.value))} /></Field>
        <Field label="Username"><input required value={draft.username} onChange={(event) => set("username", event.target.value)} /></Field>
        <Field label="Auth type">
          <select value={draft.authType} onChange={(event) => set("authType", event.target.value as AuthType)}>
            <option value="password">Password</option>
            <option value="private-key">Private key</option>
          </select>
        </Field>
        {draft.authType === "password" ? (
          <SecretField
            label={draft.mode === "edit" ? "Password (blank keeps current)" : "Password"}
            value={draft.password ?? ""}
            onChange={(value) => set("password", value)}
            placeholder={draft.mode === "edit" ? "Stored password is hidden; enter a new value to replace" : ""}
          />
        ) : (
          <Field label="Private key">
            <select value={draft.privateKeyId ?? ""} onChange={(event) => set("privateKeyId", event.target.value)}>
              <option value="">Select private key</option>
              {keys.map((key) => (
                <option key={key.id} value={key.id}>{key.name}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Expected server fingerprint">
          <input value={draft.expectedServerFingerprint} onChange={(event) => set("expectedServerFingerprint", event.target.value)} />
        </Field>
        <Field label="Keepalive interval, sec">
          <input type="number" min={60} max={3600} value={draft.keepaliveIntervalSec} onChange={(event) => set("keepaliveIntervalSec", Number(event.target.value))} />
        </Field>
        <label className="field wide">
          <span>Note</span>
          <textarea value={draft.note} onChange={(event) => set("note", event.target.value)} />
        </label>
      </div>
      <div className="modal-actions">
        <button type="button" className="ghost-button" onClick={onCancel}>Cancel</button>
        <button type="submit" className="primary-button"><Save size={16} /> Save</button>
      </div>
    </form>
  );
}
