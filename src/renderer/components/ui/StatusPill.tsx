export function StatusPill({ state }: { state: string }): JSX.Element {
  return <div className={`status-pill ${state.toLowerCase()}`} role="status" aria-live="polite">{state}</div>;
}
