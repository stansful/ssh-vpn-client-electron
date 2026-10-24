import type { ServiceEvent } from "../shared/ipc.js";
import type { ConnectRequest, RoutingRule, RoutingUpdateRequest, RuntimeStatus, SshConfig, TunnelCheckResult } from "../shared/types.js";

export interface ServiceBridge {
  onEvent(listener: (event: ServiceEvent) => void): () => void;
  getStatus(): RuntimeStatus;
  updateConfig(config: SshConfig): Promise<void>;
  updateRoutingRules(rules: RoutingRule[]): Promise<void>;
  updateRouting(request: RoutingUpdateRequest): Promise<void>;
  connect(request: ConnectRequest): Promise<void>;
  disconnect(): Promise<void>;
  checkTunnel(endpoint: string): Promise<TunnelCheckResult>;
  openTerminal(): Promise<void>;
  closeTerminal(): Promise<void>;
  terminalInput(input: string): Promise<void>;
  /**
   * Tells the service that the machine resumed, changed networks or was
   * otherwise frozen, so it can re-check a live session and bring a waiting
   * reconnect forward. Optional: simulators and remote services ignore it.
   */
  wake?(reason: string): void;
  /**
   * Leaves the Error state and returns to Disconnected without connecting.
   * Routing is already torn down in Error, so this only resets the status.
   */
  clearError?(): Promise<void>;
  /**
   * The part of disconnect() that must not wait its turn: the session is
   * marked as ending, and a connect or TUN start in flight stops being waited
   * for. Main calls it before it queues the disconnect behind whatever it is
   * running - a Connect, a routing update - which would otherwise sit out
   * that work's own timeouts first; the queued disconnect() then tears down.
   * Does nothing unless a session is live or on its way. Optional:
   * simulators and remote services leave the disconnect to its turn.
   */
  beginDisconnect?(): void;
  dispose?(): Promise<void>;
}
