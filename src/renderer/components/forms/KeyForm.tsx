import { Clipboard, Save } from "lucide-react";
import type { FormEvent } from "react";
import type { KeyDraft } from "../../types.js";
import { Field } from "../ui/index.js";
import { SecretField } from "./SecretField.js";

export function KeyForm({
  draft,
  error,
  busy,
  onChange,
  onSubmit,
  onCancel,
  onCopySavedPrivateKey
}: {
  draft: KeyDraft;
  error: string;
  busy: boolean;
  onChange: (draft: KeyDraft) => void;
  onSubmit: (event: FormEvent) => void;
  onCancel: () => void;
  onCopySavedPrivateKey: (id: string | undefined) => void;
}): JSX.Element {
  const set = <K extends keyof KeyDraft>(key: K, value: KeyDraft[K]): void => onChange({ ...draft, [key]: value });
  return (
    <form className="modal-form" aria-busy={busy} onSubmit={onSubmit}>
      {error && (
        <div
          className={error.includes("copied") ? "inline-success modal-error" : "inline-error modal-error"}
          role={error.includes("copied") ? "status" : "alert"}
        >
          {error}
        </div>
      )}
      <fieldset className="modal-fieldset" disabled={busy}>
        <Field label="Key name"><input required value={draft.name} onChange={(event) => set("name", event.target.value)} /></Field>
        <SecretField
          label={draft.mode === "edit" ? "Private key (blank keeps current)" : "Private key"}
          value={draft.privateKey ?? ""}
          onChange={(value) => set("privateKey", value)}
          multiline
          placeholder={draft.mode === "edit" ? "Stored private key is hidden; paste a new key to replace" : ""}
        />
        {draft.mode === "edit" && (
          <div className="inline-actions">
            <button type="button" className="ghost-button" disabled={busy} onClick={() => onCopySavedPrivateKey(draft.id)}>
              <Clipboard size={16} /> Copy saved private key
            </button>
          </div>
        )}
        <SecretField
          label={draft.mode === "edit" ? "Key passphrase (blank keeps current)" : "Key passphrase"}
          value={draft.privateKeyPassphrase ?? ""}
          onChange={(value) => set("privateKeyPassphrase", value)}
          placeholder={draft.mode === "edit" ? "Stored passphrase is hidden; enter a new value to replace" : ""}
        />
        <div className="modal-actions">
          <button type="button" className="ghost-button" disabled={busy} onClick={onCancel}>Cancel</button>
          <button type="submit" className="primary-button" disabled={busy}><Save size={16} /> {busy ? "Saving…" : "Save"}</button>
        </div>
      </fieldset>
    </form>
  );
}
