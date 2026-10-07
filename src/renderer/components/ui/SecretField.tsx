import { Check, ClipboardPaste, Copy, Eye, EyeOff, Lock, type LucideIcon } from "lucide-react";
import { forwardRef, useState, type InputHTMLAttributes } from "react";
import { Button } from "./Button.js";
import { useFieldControl } from "./Field.js";
import { cx, Icon } from "./Icon.js";
import { TextArea, type TextAreaProps } from "./TextInput.js";
import { useCopyFeedback, usePasteFromClipboard } from "./useClipboard.js";

export interface SecretInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange" | "type"> {
  value: string;
  onValueChange: (value: string) => void;
  /** Lower-case name used in accessible labels: "password", "passphrase". Default "secret". */
  secretName?: string;
  /** Inline Copy button for what was typed. Default true. */
  copyable?: boolean;
  /** Inline Paste button (reads the clipboard through the main process). Default false. */
  pasteable?: boolean;
  /** Called after a successful paste (e.g. to show a "pasted" state line). */
  onPasted?: (text: string) => void;
  /** Leading glyph inside the box. Default a lock; null for none. */
  leadingIcon?: LucideIcon | null;
  /** Mono text while shown (keys, tokens). */
  mono?: boolean;
  invalid?: boolean;
}

/**
 * Secret text box: hidden by default, with inline Show / Copy (and optional
 * Paste) that confirm with "Copied" and announce it politely.
 */
export const SecretInput = forwardRef<HTMLInputElement, SecretInputProps>(function SecretInput(
  {
    value,
    onValueChange,
    secretName = "secret",
    copyable = true,
    pasteable = false,
    onPasted,
    leadingIcon = Lock,
    mono = false,
    invalid,
    id,
    disabled,
    className,
    autoComplete = "new-password",
    "aria-describedby": describedBy,
    ...rest
  },
  ref
) {
  const field = useFieldControl();
  const [shown, setShown] = useState(false);
  const [live, setLive] = useState("");
  const { copied, copy } = useCopyFeedback();
  const paste = usePasteFromClipboard();
  const isInvalid = invalid ?? field?.invalid ?? false;
  const isDisabled = disabled ?? field?.disabled ?? false;
  const showLabel = `${shown ? "Hide" : "Show"} ${secretName}`;

  return (
    <div className={cx("secret", isInvalid && "is-invalid", className)} data-disabled={isDisabled ? "true" : undefined}>
      {leadingIcon ? <Icon icon={leadingIcon} size="sm" /> : null}
      <input
        ref={ref}
        id={id ?? field?.id}
        type={shown ? "text" : "password"}
        className={cx(shown && mono && "mono")}
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
        autoComplete={autoComplete}
        spellCheck={false}
        disabled={isDisabled}
        aria-invalid={isInvalid || undefined}
        aria-describedby={[describedBy, field?.describedBy].filter(Boolean).join(" ") || undefined}
        {...rest}
      />
      <button
        type="button"
        className="secret-btn"
        aria-pressed={shown}
        aria-label={showLabel}
        title={showLabel}
        disabled={isDisabled}
        onClick={() => setShown((current) => !current)}
      >
        <Icon icon={shown ? EyeOff : Eye} />
        {shown ? "Hide" : "Show"}
      </button>
      {copyable ? (
        <>
          <span className="secret-sep" aria-hidden="true" />
          <button
            type="button"
            className="secret-btn"
            data-done={copied ? "true" : undefined}
            aria-label={`Copy ${secretName} you typed`}
            title={value ? "Copy what you typed" : "Type something to copy it"}
            disabled={isDisabled || value.length === 0}
            onClick={() => {
              void copy(value).then((ok) => setLive(ok ? "Copied to the clipboard." : ""));
            }}
          >
            <span className="secret-inner" key={copied ? "copied" : "copy"}>
              <Icon icon={copied ? Check : Copy} />
              {copied ? "Copied" : "Copy"}
            </span>
          </button>
        </>
      ) : null}
      {pasteable ? (
        <>
          <span className="secret-sep" aria-hidden="true" />
          <button
            type="button"
            className="secret-btn"
            aria-label={`Paste ${secretName} from clipboard`}
            title="Paste from clipboard"
            disabled={isDisabled}
            onClick={() => {
              void paste().then((text) => {
                if (text !== undefined) {
                  onValueChange(text);
                  onPasted?.(text);
                  setLive("Pasted from the clipboard.");
                }
              });
            }}
          >
            <Icon icon={ClipboardPaste} />
            Paste
          </button>
        </>
      ) : null}
      <span className="sr-only" aria-live="polite">
        {live}
      </span>
    </div>
  );
});

export interface SecretTextAreaProps extends Omit<TextAreaProps, "masked" | "value" | "onChange"> {
  value: string;
  onValueChange: (value: string) => void;
  /** Controlled visibility; pair with a RevealButton in the Field's label row. */
  shown: boolean;
}

/** Multi-line secret (private keys): masked with -webkit-text-security, line structure kept. */
export const SecretTextArea = forwardRef<HTMLTextAreaElement, SecretTextAreaProps>(function SecretTextArea(
  { value, onValueChange, shown, className, autoComplete = "off", wrap = "off", ...rest },
  ref
) {
  return (
    <TextArea
      ref={ref}
      value={value}
      onChange={(event) => onValueChange(event.target.value)}
      masked={!shown}
      className={cx("secret-area", className)}
      autoComplete={autoComplete}
      wrap={wrap}
      {...rest}
    />
  );
});

export interface RevealButtonProps {
  shown: boolean;
  onShownChange: (shown: boolean) => void;
  /** Lower-case name for the accessible label: "private key". */
  secretName: string;
  disabled?: boolean;
}

/** "Show / Hide" ghost button for a label row (aria-pressed). */
export function RevealButton({ shown, onShownChange, secretName, disabled }: RevealButtonProps): JSX.Element {
  const label = `${shown ? "Hide" : "Show"} ${secretName}`;
  return (
    <Button
      variant="ghost"
      size="sm"
      icon={shown ? EyeOff : Eye}
      aria-pressed={shown}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={() => onShownChange(!shown)}
    >
      {shown ? "Hide" : "Show"}
    </Button>
  );
}

export interface PasteButtonProps {
  /** Receives the clipboard text (nothing happens when the clipboard is empty). */
  onPaste: (text: string) => void;
  /** Accessible name naming the target: "Paste private key from clipboard". */
  label: string;
  disabled?: boolean;
}

/** "Paste" ghost button that reads the clipboard through the main process. */
export function PasteButton({ onPaste, label, disabled }: PasteButtonProps): JSX.Element {
  const paste = usePasteFromClipboard();
  const [busy, setBusy] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      icon={ClipboardPaste}
      aria-label={label}
      title={label}
      disabled={disabled}
      busy={busy}
      onClick={() => {
        setBusy(true);
        void paste()
          .then((text) => {
            if (text !== undefined) {
              onPaste(text);
            }
          })
          .finally(() => setBusy(false));
      }}
    >
      Paste
    </Button>
  );
}
