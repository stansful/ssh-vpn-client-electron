export function NavButton({
  active,
  compact = false,
  icon,
  label,
  onClick
}: {
  active: boolean;
  compact?: boolean;
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}): JSX.Element {
  return (
    <button
      type="button"
      className={active ? "nav-button active" : "nav-button"}
      aria-current={active ? "page" : undefined}
      aria-label={label}
      title={compact ? label : undefined}
      onClick={onClick}
    >
      <span className="nav-icon" aria-hidden="true">{icon}</span>
      <span className="nav-label-text">{label}</span>
    </button>
  );
}
