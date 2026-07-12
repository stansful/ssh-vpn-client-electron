import type { AppStore, ConnectionState } from "../../shared/types.js";
import { validateRoutingRuleValue } from "../../shared/validation.js";
import { normalizeProxyDomain } from "../../core/routing/domain-proxy-list.js";

export type SelectedRoutingTargetState = Pick<AppStore, "routingRules" | "routingProxyList">;
export type RoutingMutationState = Pick<AppStore, "routingMode" | "routingRules" | "routingProxyList" | "routingDirectList">;
export type RoutingMutationAction = "apply" | "disconnect" | "idle";

export function hasSelectedRoutingTargets(store: SelectedRoutingTargetState): boolean {
  return (
    store.routingRules.some((rule) => rule.enabled && validateRoutingRuleValue(rule.type, rule.value).ok) ||
    (store.routingProxyList.enabled && store.routingProxyList.domains.some((domain) => normalizeProxyDomain(domain) !== undefined))
  );
}

export function routingMutationAction(store: RoutingMutationState, connectionState: ConnectionState): RoutingMutationAction {
  if (store.routingMode !== "selected-rules" || hasSelectedRoutingTargets(store)) {
    return "apply";
  }
  return connectionState === "Disconnected" || connectionState === "Disconnecting" ? "idle" : "disconnect";
}
