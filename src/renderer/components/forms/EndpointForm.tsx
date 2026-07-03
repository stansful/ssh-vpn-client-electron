import { Save } from "lucide-react";
import type { FormEvent } from "react";
import { Field } from "../ui/index.js";

export function EndpointForm({
  value,
  error,
  onChange,
  onSubmit,
  onCancel
}: {
  value: string;
  error: string;
  onChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onCancel: () => void;
}): JSX.Element {
  return (
    <form className="modal-form" onSubmit={onSubmit}>
      {error && <div className="inline-error modal-error">{error}</div>}
      <Field label="Endpoint">
        <input value={value} onChange={(event) => onChange(event.target.value)} placeholder="youtube.com:443" />
      </Field>
      <div className="modal-actions">
        <button type="button" className="ghost-button" onClick={onCancel}>Cancel</button>
        <button type="submit" className="primary-button"><Save size={16} /> Save</button>
      </div>
    </form>
  );
}
