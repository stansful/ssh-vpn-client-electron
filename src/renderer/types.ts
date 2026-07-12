import type { UpsertSshConfigInput, UpsertSshKeyInput } from "../shared/types.js";

export type View = "main" | "configs" | "keys" | "routing" | "logs" | "settings";
export type RoutingSaveState = "idle" | "saving" | "saved" | "error";

export interface ConfigDraft extends UpsertSshConfigInput {
  mode: "create" | "edit";
}

export interface KeyDraft extends UpsertSshKeyInput {
  mode: "create" | "edit";
}

export const MAX_RENDERER_DIAGNOSTICS = 500;

export const emptyConfigDraft = (): ConfigDraft => ({
  mode: "create",
  name: "",
  host: "",
  port: 22,
  username: "",
  authType: "password",
  password: "",
  privateKeyId: "",
  expectedServerFingerprint: "",
  keepaliveIntervalSec: 120,
  note: ""
});

export const emptyKeyDraft = (): KeyDraft => ({
  mode: "create",
  name: "",
  privateKey: "",
  privateKeyPassphrase: ""
});
