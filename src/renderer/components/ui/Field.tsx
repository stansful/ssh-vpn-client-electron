import { CircleAlert } from "lucide-react";
import { createContext, useContext, useId, type ReactNode } from "react";
import { cx, Icon } from "./Icon.js";

export interface FieldControlProps {
  /** id for the control, linked to the label. */
  id: string;
  /** Hint and error ids for aria-describedby. */
  describedBy?: string;
  invalid: boolean;
  disabled?: boolean;
}

const FieldContext = createContext<FieldControlProps | null>(null);

/** Inside a Field: the id/aria wiring for its control. Inputs in this kit pick it up automatically. */
export function useFieldControl(): FieldControlProps | null {
  return useContext(FieldContext);
}

export interface FieldProps {
  label: ReactNode;
  /** Adds a quiet "optional" mark after the label. */
  optional?: boolean;
  /** Badges or tools at the right end of the label row (Saved, Paste, Show). */
  labelAside?: ReactNode;
  /** Help under the control. Replaced by `error` while there is one. */
  hint?: ReactNode;
  /** Says what is wrong and how to fix it; announced as an alert. */
  error?: ReactNode;
  /** Use a given id for the control instead of a generated one. */
  id?: string;
  disabled?: boolean;
  /** Content between the control and the hint (state lines, suggestions). */
  after?: ReactNode;
  /** Keep the hint visible under the error instead of replacing it. */
  keepHint?: boolean;
  className?: string;
  /** The control. Kit inputs read the ids from context; custom controls can use the render form. */
  children: ReactNode | ((control: FieldControlProps) => ReactNode);
}

/** Label above, hint below, error replaces the hint (`.field`). */
export function Field({ label, optional, labelAside, hint, error, id, disabled, after, keepHint = false, className, children }: FieldProps): JSX.Element {
  const generated = useId();
  const controlId = id ?? `field-${generated}`;
  const hintId = `${controlId}-hint`;
  const errorId = `${controlId}-error`;
  const showHint = Boolean(hint) && (!error || keepHint);
  const describedBy = [error ? errorId : undefined, showHint ? hintId : undefined].filter(Boolean).join(" ") || undefined;
  const control: FieldControlProps = { id: controlId, describedBy, invalid: Boolean(error), disabled };

  const labelNode = (
    <label className="label" htmlFor={controlId}>
      {label}
      {optional ? <span className="opt">optional</span> : null}
    </label>
  );

  return (
    <div className={cx("field", className)}>
      {labelAside ? (
        <div className="label-row">
          {labelNode}
          <div className="label-tools">{labelAside}</div>
        </div>
      ) : (
        labelNode
      )}
      <FieldContext.Provider value={control}>{typeof children === "function" ? children(control) : children}</FieldContext.Provider>
      {after}
      {error ? <FieldError id={errorId}>{error}</FieldError> : null}
      {showHint ? (
        <span className="hint" id={hintId}>
          {hint}
        </span>
      ) : null}
    </div>
  );
}

/** Inline validation message with the alert glyph the form boards use; announced as an alert. */
export function FieldError({ id, children }: { id?: string; children: ReactNode }): JSX.Element {
  return (
    <span className="error-text anim-swap" id={id} role="alert">
      <Icon icon={CircleAlert} size="sm" />
      <span>{children}</span>
    </span>
  );
}

/** Quiet help text (`.hint`). */
export function Hint({ id, children, tone }: { id?: string; children: ReactNode; tone?: "ok" }): JSX.Element {
  return (
    <span className={cx("hint", tone === "ok" && "t-ok")} id={id}>
      {children}
    </span>
  );
}
