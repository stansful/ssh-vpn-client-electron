import { Check, Copy } from "lucide-react";
import { IconButton, Button, type ButtonSize, type ButtonVariant } from "./Button.js";
import { useCopyFeedback } from "./useClipboard.js";

export interface CopyButtonProps {
  /** Text to copy (read when clicked). */
  text: string | (() => string);
  /** Accessible name naming what is copied: "Copy local proxy address". */
  label: string;
  /** Show a text button ("Copy" → "Copied") instead of an icon button. */
  withText?: boolean;
  /** Visible text for `withText`. Default "Copy". */
  children?: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  disabled?: boolean;
  className?: string;
  /** Called after a successful copy. */
  onCopied?: () => void;
}

/** Copy action with a 1.6 s "Copied" check; failures become an error toast. */
export function CopyButton({ text, label, withText = false, children = "Copy", variant = "ghost", size = "sm", disabled, className, onCopied }: CopyButtonProps): JSX.Element {
  const { copied, copy } = useCopyFeedback();
  const handleClick = (): void => {
    void copy(typeof text === "function" ? text() : text).then((ok) => {
      if (ok) {
        onCopied?.();
      }
    });
  };
  if (withText) {
    return (
      <Button variant={variant} size={size} icon={copied ? Check : Copy} done={copied} aria-label={label} title={label} disabled={disabled} className={className} onClick={handleClick}>
        <span className="btn-label-swap" key={copied ? "copied" : "copy"} aria-live="polite">
          {copied ? "Copied" : children}
        </span>
      </Button>
    );
  }
  return (
    <IconButton
      icon={Copy}
      label={label}
      tooltip={copied ? "Copied" : "Copy"}
      variant={variant}
      size={size}
      done={copied}
      disabled={disabled}
      className={className}
      onClick={handleClick}
    />
  );
}
