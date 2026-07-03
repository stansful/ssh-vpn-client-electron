export function EmptyState({ text, action }: { text: string; action?: React.ReactNode }): JSX.Element {
  return (
    <div className="empty-state">
      <span>{text}</span>
      {action}
    </div>
  );
}
