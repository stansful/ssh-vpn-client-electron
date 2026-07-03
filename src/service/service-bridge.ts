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
  dispose?(): Promise<void>;
}
