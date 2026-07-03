import { StatusPill } from "../ui/index.js";

export function Topbar({ title, message, state }: { title: string; message: string | undefined; state: string }): JSX.Element {
  return (
    <header className="topbar">
      <div>
        <h1>{title}</h1>
        <p>{message}</p>
      </div>
      <StatusPill state={state} />
    </header>
  );
}
