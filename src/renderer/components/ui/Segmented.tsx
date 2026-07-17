import { useRef, type KeyboardEvent } from "react";

export function Segmented<T extends string>({
  value,
  options,
  ariaLabel,
  onChange
}: {
  value: T;
  options: Array<[T, string]>;
  ariaLabel: string;
  onChange: (value: T) => void;
}): JSX.Element {
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) {
      return;
    }
    event.preventDefault();
    const nextIndex = event.key === "Home"
      ? 0
      : event.key === "End"
        ? options.length - 1
        : (index + (event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
    if (options[nextIndex][0] !== value) {
      onChange(options[nextIndex][0]);
    }
    buttons.current[nextIndex]?.focus();
  }

  return (
    <div className="segmented" role="radiogroup" aria-label={ariaLabel}>
      {options.map(([option, label], index) => (
        <button
          ref={(element) => { buttons.current[index] = element; }}
          key={option}
          type="button"
          role="radio"
          aria-checked={value === option}
          tabIndex={value === option ? 0 : -1}
          className={value === option ? "active" : ""}
          onKeyDown={(event) => handleKeyDown(event, index)}
          onClick={() => option !== value && onChange(option)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}
