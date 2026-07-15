import { Clipboard, Eye, EyeOff } from "lucide-react";
import { useId, useState } from "react";
import { api } from "../../api.js";

export function SecretField({
  label,
  value,
  onChange,
  placeholder,
  multiline = false
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  multiline?: boolean;
}): JSX.Element {
  const [visible, setVisible] = useState(false);
  const inputId = useId();
  const copyValue = (): void => {
    if (value) {
      void api.copyText(value).catch(() => undefined);
    }
  };
  const control = multiline ? (
    <textarea
      id={inputId}
      className={visible ? "secret-textarea secret-input" : "secret-textarea secret-input masked"}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
    />
  ) : (
    <input
      id={inputId}
      className="secret-input"
      type={visible ? "text" : "password"}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
    />
  );

  return (
    <div className="field secret-field">
      <label htmlFor={inputId}><span>{label}</span></label>
      <div className="secret-control">
        {control}
        <div className="secret-actions">
          <button type="button" className="icon-button" onClick={() => setVisible((current) => !current)} aria-controls={inputId} aria-label={visible ? "Hide secret" : "Show secret"}>
            {visible ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
          <button type="button" className="icon-button" disabled={!value} onClick={copyValue} aria-label="Copy secret">
            <Clipboard size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}
