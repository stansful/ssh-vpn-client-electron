import { Activity } from "lucide-react";
import { useAppData } from "../../../hooks/useAppData.js";
import { formatClock } from "../../../lib/format.js";
import { Card, CardHeader, LevelPill, LinkButton } from "../../ui/index.js";

const RECENT_COUNT = 4;

/** The last few events, newest first, with the way to Activity. */
export function RecentActivityCard(): JSX.Element {
  const { snapshot, navigate } = useAppData();
  const recent = snapshot.diagnostics.slice(-RECENT_COUNT).reverse();

  return (
    <Card rise={4} aria-label="Recent activity">
      <CardHeader icon={Activity} title="Recent activity" sub="What the tunnel did, including events that used to hide in the log." />
      {recent.length > 0 ? (
        <div className="feed">
          {recent.map((entry) => (
            <div className="feed-row" key={entry.id}>
              <span className="feed-time">{formatClock(entry.at)}</span>
              <LevelPill level={entry.level} />
              <span className="feed-msg">{entry.message.split(/\r?\n/u, 1)[0]}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="hint cn-feed-empty">Nothing yet. Events show up here as soon as the tunnel does something.</p>
      )}
      <LinkButton onClick={() => navigate("activity")}>Open activity</LinkButton>
    </Card>
  );
}
