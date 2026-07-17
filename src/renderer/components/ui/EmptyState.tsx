import { Sparkles } from "lucide-react";

export function EmptyState({ text, action }: { text: string; action?: React.ReactNode }): JSX.Element {
  return (
    <div className="empty-state">
      <span className="empty-state-icon" aria-hidden="true"><Sparkles size={18} /></span>
      <strong className="empty-state-title">Nothing here yet</strong>
      <span>{text}</span>
      {action}
    </div>
  );
}
