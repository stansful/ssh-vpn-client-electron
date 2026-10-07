import { useId, type CSSProperties } from "react";
import { cx } from "../../ui/index.js";
import { HEX_FIELD_ERROR, normalizeHexInput } from "./settings-model.js";

export interface ColorFieldProps {
  name: string;
  /** Colour in use, "#F6A019". */
  hex: string;
  hint: string;
  /** What the HEX box holds while someone is typing (may be invalid). */
  draft?: string;
  disabled?: boolean;
  /** Typing in the HEX box; `hex` is set when the text is a valid colour. */
  onDraft: (raw: string, hex: string | undefined) => void;
  /** A colour from the native picker. */
  onPick: (hex: string) => void;
  /** Leaving the HEX box drops the draft (an invalid one reverts to `hex`). */
  onDraftEnd: () => void;
}

/** Swatch (native colour picker) + HEX input, as on Settings.dc.html. */
export function ColorField({ name, hex, hint, draft, disabled = false, onDraft, onPick, onDraftEnd }: ColorFieldProps): JSX.Element {
  const id = useId();
  const hintId = `${id}-hint`;
  const invalid = draft !== undefined && !normalizeHexInput(draft);
  return (
    <div className="st-cf">
      <label className="label" htmlFor={id}>
        {name}
      </label>
      <div className="st-cf-row">
        <label className="st-swatch" style={{ "--c": hex } as CSSProperties} title={disabled ? undefined : "Open colour picker"}>
          <input
            type="color"
            value={hex.toLowerCase()}
            aria-label={`Pick ${name} colour`}
            disabled={disabled}
            onChange={(event) => {
              const picked = normalizeHexInput(event.target.value);
              if (picked) {
                onPick(picked);
              }
            }}
          />
        </label>
        <input
          id={id}
          className={cx("input mono st-hex", invalid && "is-invalid")}
          type="text"
          value={draft ?? hex}
          maxLength={7}
          spellCheck={false}
          autoComplete="off"
          aria-invalid={invalid || undefined}
          aria-describedby={hintId}
          disabled={disabled}
          onChange={(event) => onDraft(event.target.value, normalizeHexInput(event.target.value))}
          onBlur={onDraftEnd}
          onKeyDown={(event) => {
            if (event.key === "Escape" && draft !== undefined) {
              event.preventDefault();
              event.stopPropagation();
              onDraftEnd();
            }
          }}
        />
      </div>
      <span className={invalid ? "error-text" : "hint"} id={hintId}>
        {invalid ? HEX_FIELD_ERROR : hint}
      </span>
    </div>
  );
}
