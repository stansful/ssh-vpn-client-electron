import { memo } from "react";
import { StatusPill } from "../ui/index.js";

export const Topbar = memo(function Topbar({ title, message, state }: { title: string; message: string | undefined; state: string }): JSX.Element {
  return (
    <header className="topbar">
      <div className="topbar-copy">
        <span className="topbar-eyebrow">Secure network control</span>
        <h1 tabIndex={-1}>{title}</h1>
        <p>{message}</p>
      </div>
      <div className="topbar-status">
        <StatusPill state={state} />
      </div>
    </header>
  );
});
