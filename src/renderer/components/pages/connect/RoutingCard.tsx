import { Route, TriangleAlert } from "lucide-react";
import { useMemo } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import { Badge, Card, CardHeader, LinkButton } from "../../ui/index.js";
import { summarizeRouting } from "./connect-target.js";

/** Routing at a glance: the mode, what goes through, and the way to Routing. */
export function RoutingCard(): JSX.Element {
  const { store, navigate } = useAppData();
  const summary = useMemo(() => summarizeRouting(store), [store]);

  return (
    <Card rise={2} aria-label="Routing">
      <CardHeader icon={Route} title={summary.title} sub={summary.sub} />
      <div className="row-wrap">
        {summary.blocked ? (
          <Badge tone="warn" icon={TriangleAlert}>
            No targets
          </Badge>
        ) : (
          summary.badges.map((badge) => (
            <Badge key={badge} tone="outline">
              {badge}
            </Badge>
          ))
        )}
      </div>
      <LinkButton onClick={() => navigate("routing")}>Manage routing</LinkButton>
    </Card>
  );
}
