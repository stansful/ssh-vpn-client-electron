import type { ConnectionState } from "../../shared/types.js";

export type ConnectionTone = "idle" | "pending" | "active" | "warning" | "error";

export interface ConnectionPresentation {
  statusLabel: string;
  title: string;
  description: string;
  tone: ConnectionTone;
  action: "connect" | "disconnect";
  actionLabel: string;
  actionDetail: string;
  actionPending: boolean;
}

export function sshConnectionPresentation(
  state: ConnectionState,
  realTunnelAvailable: boolean,
  runtimeMessage?: string
): ConnectionPresentation {
  if (state === "Connecting") {
    return {
      statusLabel: "Starting",
      title: "Establishing SSH tunnel",
      description: usefulRuntimeMessage(runtimeMessage, "Opening the encrypted session and preparing traffic routing."),
      tone: "pending",
      action: "disconnect",
      actionLabel: "Connecting…",
      actionDetail: "Opening secure tunnel",
      actionPending: true
    };
  }

  if (state === "Connected") {
    if (!realTunnelAvailable) {
      return {
        statusLabel: "Preview only",
        title: "Connected without system routing",
        description: usefulRuntimeMessage(runtimeMessage, "This runtime cannot redirect device traffic through the tunnel."),
        tone: "warning",
        action: "disconnect",
        actionLabel: "Disconnect",
        actionDetail: "Stop this session",
        actionPending: false
      };
    }
    return {
      statusLabel: "Protected",
      title: "SSH tunnel is active",
      description: usefulRuntimeMessage(runtimeMessage, "The encrypted proxy and traffic routing are running."),
      tone: "active",
      action: "disconnect",
      actionLabel: "Disconnect",
      actionDetail: "Stop secure routing",
      actionPending: false
    };
  }

  if (state === "Reconnecting") {
    return {
      statusLabel: "Restoring",
      title: "Restoring SSH connection",
      description: usefulRuntimeMessage(runtimeMessage, "The previous session was interrupted. Shadow SSH is reconnecting."),
      tone: "pending",
      action: "disconnect",
      actionLabel: "Disconnect",
      actionDetail: "Stop reconnecting",
      actionPending: false
    };
  }

  if (state === "Disconnecting") {
    return {
      statusLabel: "Stopping",
      title: "Closing SSH tunnel",
      description: usefulRuntimeMessage(runtimeMessage, "Restoring direct network settings and closing the session."),
      tone: "pending",
      action: "disconnect",
      actionLabel: "Disconnecting…",
      actionDetail: "Please wait",
      actionPending: true
    };
  }

  if (state === "Error") {
    return {
      statusLabel: "Needs attention",
      title: "Connection failed",
      description: usefulRuntimeMessage(runtimeMessage, "Review the selected configuration and try again."),
      tone: "error",
      action: "connect",
      actionLabel: "Try again",
      actionDetail: "Retry selected server",
      actionPending: false
    };
  }

  return {
    statusLabel: "Tunnel off",
    title: "Ready to connect",
    description: "Choose a saved SSH configuration, then start the secure tunnel.",
    tone: "idle",
    action: "connect",
    actionLabel: "Connect",
    actionDetail: "Start secure routing",
    actionPending: false
  };
}

export function isConnectionSelectionLocked(state: ConnectionState): boolean {
  return state !== "Disconnected" && state !== "Error";
}

function usefulRuntimeMessage(message: string | undefined, fallback: string): string {
  const trimmed = message?.trim();
  if (!trimmed || trimmed === "Disconnected." || trimmed === "Connected.") {
    return fallback;
  }
  return trimmed;
}
