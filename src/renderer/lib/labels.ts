import type { RoutingSaveState, View } from "../types.js";
import type { RoutingRuleType } from "../../shared/types.js";

export function titleForView(view: View): string {
  const titles: Record<View, string> = {
    main: "Main screen",
    configs: "SSH configurations",
    keys: "SSH keys",
    routing: "Routing rules",
    logs: "Logs",
    settings: "Settings"
  };
  return titles[view];
}

export function placeholderForRule(type: RoutingRuleType): string {
  if (type === "domain") {
    return "youtube.com or *.youtube.com";
  }
  if (type === "ip") {
    return "8.8.8.8 or 2a00:1450::/32";
  }
  return "chrome.exe";
}

export function checkButtonClass(ok: boolean | undefined, checking: boolean): string {
  if (checking) {
    return "check-button checking";
  }
  if (ok === true) {
    return "check-button success";
  }
  if (ok === false) {
    return "check-button failure";
  }
  return "check-button";
}

export function routingSaveLabel(state: RoutingSaveState): string {
  if (state === "saving") {
    return "Saving...";
  }
  if (state === "saved") {
    return "Saved";
  }
  if (state === "error") {
    return "Save failed";
  }
  return "Autosave";
}

export function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
