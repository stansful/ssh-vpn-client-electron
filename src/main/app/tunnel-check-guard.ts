import type { ConnectionState, GlobalTab, RuntimeStatus } from "../../shared/types.js";

/** What a check remembers about the session it started on. */
export interface TunnelCheckTicket {
  transport: GlobalTab;
  generation: number;
  /** The server or profile name when the check started; the result is labelled with it. */
  targetName?: string;
}

/** A check result describes a running tunnel. */
export function isCheckableState(state: ConnectionState): boolean {
  return state === "Connected" || state === "Reconnecting";
}

/**
 * Ties a tunnel check to the session it started on. A probe can outlive that
 * session - the user switches servers or disconnects while it runs, and
 * closing the session is exactly what makes it fail - and such a result must
 * not come back as the next session's check, under the next session's name.
 */
export class TunnelCheckSessionGuard {
  private generation = 0;
  private sessionKey: string | undefined;

  /** A new connect starts a new session before its first status arrives. */
  reset(): void {
    this.generation += 1;
    this.sessionKey = undefined;
  }

  /** Called with every status of the active transport. */
  observe(transport: GlobalTab, status: Pick<RuntimeStatus, "state" | "activeConfigId" | "connectedAt">): void {
    const key = isCheckableState(status.state)
      ? `${transport}:${status.activeConfigId ?? ""}:${status.connectedAt ?? ""}`
      : undefined;
    if (key !== this.sessionKey) {
      this.sessionKey = key;
      this.generation += 1;
    }
  }

  begin(transport: GlobalTab, targetName?: string): TunnelCheckTicket {
    return { transport, generation: this.generation, ...(targetName ? { targetName } : {}) };
  }

  /** Whether a finished check still describes the session that runs now. */
  accepts(ticket: TunnelCheckTicket, activeTransport: GlobalTab, state: ConnectionState): boolean {
    return ticket.generation === this.generation && ticket.transport === activeTransport && isCheckableState(state);
  }
}
