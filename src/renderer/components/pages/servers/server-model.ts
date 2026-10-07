import { isPreviewSession } from "../../../lib/connection.js";
import { formatSshTarget } from "../../../lib/format.js";
import type { AppSnapshot, SshConfig, SshKeyMetadata } from "../../../../shared/types.js";

/** How the SSH session relates to the saved servers. */
export interface SshSessionView {
  /** An SSH session is starting, up or reconnecting. */
  on: boolean;
  /** Which of those it is; "preview" is a simulated session that routes nothing. */
  state?: "connecting" | "connected" | "reconnecting" | "preview";
  /** Server the session runs (may no longer be saved). */
  activeId?: string;
  /** Name the session started with (survives renames and deletes). */
  activeName?: string;
}

export function sshSessionView(snapshot: Pick<AppSnapshot, "activeTransport" | "runtime">): SshSessionView {
  const { runtime } = snapshot;
  if (snapshot.activeTransport !== "ssh") {
    return { on: false };
  }
  const state =
    runtime.state === "Connected"
      ? isPreviewSession(runtime)
        ? "preview"
        : "connected"
      : runtime.state === "Connecting"
        ? "connecting"
        : runtime.state === "Reconnecting"
          ? "reconnecting"
          : undefined;
  if (!state) {
    return { on: false };
  }
  return { on: true, state, activeId: runtime.activeConfigId, activeName: runtime.activeConfigName };
}

/** Search looks at server names, hosts and usernames; every word must match. */
export function filterServers<T extends Pick<SshConfig, "name" | "host" | "username">>(configs: readonly T[], query: string): T[] {
  const words = query.trim().toLowerCase().split(/\s+/u).filter(Boolean);
  if (words.length === 0) {
    return [...configs];
  }
  return configs.filter((config) => {
    const haystack = `${config.name} ${config.host} ${config.username}`.toLowerCase();
    return words.every((word) => haystack.includes(word));
  });
}

/** "no matches", "1 match", "3 matches". */
export function matchLabel(count: number): string {
  return count === 0 ? "no matches" : `${count} ${count === 1 ? "match" : "matches"}`;
}

export type ServerSignIn =
  | { kind: "password"; saved: boolean }
  | { kind: "key"; key?: SshKeyMetadata };

export function serverSignIn(config: SshConfig, keys: readonly SshKeyMetadata[]): ServerSignIn {
  if (config.authType === "private-key") {
    return { kind: "key", key: keys.find((key) => key.id === config.privateKeyId) };
  }
  return { kind: "password", saved: Boolean(config.passwordSecretId) };
}

export interface ServerDeleteCopy {
  title: string;
  description: string;
  /** The session runs on this server right now. */
  live: boolean;
  /** "Connect will use … next." when the deleted server is the one Connect uses. */
  nextLine?: string;
}

export function serverDeleteCopy(
  config: SshConfig,
  context: { configs: readonly SshConfig[]; keys: readonly SshKeyMetadata[]; selectedId?: string; session: SshSessionView }
): ServerDeleteCopy {
  const key = config.authType === "private-key" ? context.keys.find((candidate) => candidate.id === config.privateKeyId) : undefined;
  const parts: string[] = [];
  if (config.passwordSecretId) {
    parts.push("The server and its saved password are removed from this device.");
  } else {
    parts.push("The server is removed from this device.");
  }
  parts.push(key ? `The key ${key.name} stays in SSH keys.` : "This can’t be undone.");

  let nextLine: string | undefined;
  if (config.id === context.selectedId) {
    const next = context.configs.find((candidate) => candidate.id !== config.id);
    nextLine = next ? `Connect will use ${next.name} next.` : "No servers will be left. Add one before you connect again.";
  }
  return {
    title: `Delete ${config.name}?`,
    description: parts.join(" "),
    live: context.session.on && context.session.activeId === config.id,
    nextLine
  };
}

export function serverDeletedMessage(config: SshConfig, context: { keys: readonly SshKeyMetadata[]; wasLive: boolean }): string {
  if (context.wasLive) {
    return `${config.name} is gone from your list. Its session keeps running until you disconnect.`;
  }
  const key = config.authType === "private-key" ? context.keys.find((candidate) => candidate.id === config.privateKeyId) : undefined;
  if (key) {
    return `${config.name} was removed. The key ${key.name} is still in SSH keys.`;
  }
  if (config.passwordSecretId) {
    return `${config.name} and its saved password were removed from this device.`;
  }
  return `${config.name} was removed from this device.`;
}

export interface CalloutCopy {
  title: string;
  message: string;
}

/** The session runs on a server that has since been deleted. */
export function liveDeletedCallout(
  configs: readonly SshConfig[],
  selectedId: string | undefined,
  session: SshSessionView
): CalloutCopy | undefined {
  if (!session.on || !session.activeId || configs.some((config) => config.id === session.activeId)) {
    return undefined;
  }
  const selected = configs.find((config) => config.id === selectedId);
  const name = session.activeName || "The server you connected to";
  return {
    title: "Still connected to a deleted server",
    message: `${name} is no longer in your list, but its session keeps running until you disconnect. ${
      selected ? `Next time, Connect uses ${selected.name}.` : "Add a server before you connect again."
    }`
  };
}

/** Another server is marked for Connect while the session still runs on the old one. */
export function upNextCallout(configs: readonly SshConfig[], selectedId: string | undefined, session: SshSessionView): CalloutCopy | undefined {
  if (!session.on || !session.activeId) {
    return undefined;
  }
  const live = configs.find((config) => config.id === session.activeId);
  const selected = configs.find((config) => config.id === selectedId);
  if (!live || !selected || live.id === selected.id) {
    return undefined;
  }
  return {
    title: `${selected.name} is up next`,
    message: `You’re still connected to ${live.name}. Connect switches to ${selected.name} the next time you connect.`
  };
}

/** "4 servers" for the list head. */
export function serverCountWord(count: number): string {
  return count === 1 ? "server" : "servers";
}

export function serverAddress(config: Pick<SshConfig, "username" | "host" | "port">): string {
  return formatSshTarget(config);
}
