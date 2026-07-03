export function StatusPill({ state }: { state: string }): JSX.Element {
  return <div className={`status-pill ${state.toLowerCase()}`}>{state}</div>;
}
