import { Save } from "lucide-react";
import type { FormEvent } from "react";
import { Field } from "../ui/index.js";

export function EndpointForm({
  value,
  error,
  busy,
  onChange,
  onSubmit,
  onCancel
}: {
  value: string;
  error: string;
  busy: boolean;
  onChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onCancel: () => void;
}): JSX.Element {
  return (
    <form className="modal-form" aria-busy={busy} onSubmit={onSubmit}>
      {error && <div className="inline-error modal-error" role="alert">{error}</div>}
      <fieldset className="modal-fieldset" disabled={busy}>
        <Field label="Endpoint">
          <input value={value} onChange={(event) => onChange(event.target.value)} placeholder="youtube.com:443" />
        </Field>
        <div className="modal-actions">
          <button type="button" className="ghost-button" disabled={busy} onClick={onCancel}>Cancel</button>
          <button type="submit" className="primary-button" disabled={busy}><Save size={16} /> {busy ? "Saving…" : "Save"}</button>
        </div>
      </fieldset>
    </form>
  );
}
