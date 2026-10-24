export interface DirectTcpIpTarget {
  host: string;
  port: number;
}

/**
 * One proxied TCP connection, whatever carries it: an SSH `direct-tcpip`
 * channel, a direct socket, or a connection through Xray's SOCKS inbound.
 */
export interface DirectTcpIpChannel {
  write(data: Buffer): Promise<void>;
  acknowledgeData?(bytes: number): Promise<void>;
  end?(): Promise<void>;
  close(): Promise<void>;
  onData(listener: (data: Buffer) => void): () => void;
  onEnd(listener: () => void): () => void;
  onClose(listener: () => void): () => void;
  onError(listener: (error: Error) => void): () => void;
}
