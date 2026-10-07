/** Top-level screens, in sidebar order. */
export type View = "connect" | "routing" | "servers" | "profiles" | "keys" | "activity" | "settings";

export type SettingsSection = "general" | "notifications" | "appearance" | "diagnostics" | "updates" | "about";
export type RoutingTab = "domains" | "ips" | "apps";

/**
 * What a page should do right after it opens. `navigate(view, intent)` passes
 * a new object every time, so pages can react in an effect keyed on it.
 */
export type NavigationIntent =
  | { type: "new-server" }
  | { type: "edit-server"; id: string }
  | { type: "new-key"; returnTo?: "server-form" }
  | { type: "edit-key"; id: string }
  | { type: "add-profile" }
  | { type: "import-profiles" }
  | { type: "routing-tab"; tab: RoutingTab }
  | { type: "settings-section"; section: SettingsSection };

/** Props every page component receives. Everything else comes from `useAppData()`. */
export interface PageProps {
  intent?: NavigationIntent;
}

export const MAX_RENDERER_DIAGNOSTICS = 500;
