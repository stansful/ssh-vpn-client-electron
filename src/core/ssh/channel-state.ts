export type ChannelLifecycle = "opening" | "open" | "eof-sent" | "eof-received" | "closed";

const MAXIMUM_OUTBOUND_CHANNEL_DATA_SIZE = 128 * 1024;

export interface ChannelState {
  localId: number;
  remoteId?: number;
  kind: "session" | "direct-tcpip";
  lifecycle: ChannelLifecycle;
  localWindow: number;
  localWindowMaximum: number;
  acknowledgedLocalBytes: number;
  remoteWindow: number;
  localMaximumPacketSize: number;
  remoteMaximumPacketSize?: number;
  /** Effective remote maximum retained for backwards compatibility. */
  maximumPacketSize: number;
}

export class ChannelStateManager {
  private readonly channels = new Map<number, ChannelState>();
  private nextLocalId = 0;

  open(kind: ChannelState["kind"], localWindow = 16 * 1024 * 1024, maximumPacketSize = 64 * 1024): ChannelState {
    const localId = this.nextLocalId;
    this.nextLocalId += 1;
    const state: ChannelState = {
      localId,
      kind,
      lifecycle: "opening",
      localWindow,
      localWindowMaximum: localWindow,
      acknowledgedLocalBytes: 0,
      remoteWindow: 0,
      localMaximumPacketSize: maximumPacketSize,
      maximumPacketSize
    };
    this.channels.set(localId, state);
    return { ...state };
  }

  confirmOpen(localId: number, remoteId: number, remoteWindow: number, maximumPacketSize: number): ChannelState {
    const state = this.require(localId);
    if (state.lifecycle !== "opening") {
      throw new Error(`Channel ${localId} is not opening.`);
    }
    if (!Number.isInteger(remoteId) || remoteId < 0 || remoteId > 0xffff_ffff) {
      throw new Error(`Channel ${localId} remote id is invalid.`);
    }
    if (!Number.isInteger(remoteWindow) || remoteWindow < 0 || remoteWindow > 0xffff_ffff) {
      throw new Error(`Channel ${localId} remote window is invalid.`);
    }
    if (!Number.isInteger(maximumPacketSize) || maximumPacketSize <= 0 || maximumPacketSize > 0xffff_ffff) {
      throw new Error(`Channel ${localId} remote maximum packet size is invalid.`);
    }
    state.remoteId = remoteId;
    state.remoteWindow = remoteWindow;
    state.remoteMaximumPacketSize = maximumPacketSize;
    state.maximumPacketSize = Math.min(maximumPacketSize, MAXIMUM_OUTBOUND_CHANNEL_DATA_SIZE);
    state.lifecycle = "open";
    return { ...state };
  }

  consumeRemoteWindow(localId: number, bytes: number): ChannelState {
    const state = this.requireCanSend(localId);
    if (bytes < 0 || !Number.isInteger(bytes)) {
      throw new Error("Window bytes must be a non-negative integer.");
    }
    if (bytes > state.remoteWindow) {
      throw new Error(`Channel ${localId} remote window exhausted.`);
    }
    state.remoteWindow -= bytes;
    return { ...state };
  }

  expandRemoteWindow(localId: number, bytes: number): ChannelState {
    const state = this.require(localId);
    if (bytes < 0 || !Number.isInteger(bytes)) {
      throw new Error("Window bytes must be a non-negative integer.");
    }
    if (state.remoteWindow + bytes > 0xffff_ffff) {
      throw new Error(`Channel ${localId} remote window overflow.`);
    }
    state.remoteWindow += bytes;
    return { ...state };
  }

  consumeLocalWindow(localId: number, bytes: number): ChannelState {
    const state = this.requireCanReceive(localId);
    if (bytes < 0 || !Number.isInteger(bytes)) {
      throw new Error("Window bytes must be a non-negative integer.");
    }
    if (bytes > state.localWindow) {
      throw new Error(`Channel ${localId} local window exhausted.`);
    }
    state.localWindow -= bytes;
    return { ...state };
  }

  replenishLocalWindow(localId: number, bytes: number): ChannelState {
    const state = this.requireCanReceive(localId);
    if (bytes < 0 || !Number.isInteger(bytes)) {
      throw new Error("Window bytes must be a non-negative integer.");
    }
    state.localWindow += bytes;
    return { ...state };
  }

  acknowledgeLocalData(localId: number, bytes: number): ChannelState {
    const state = this.require(localId);
    if (bytes < 0 || !Number.isInteger(bytes)) {
      throw new Error("Acknowledged channel bytes must be a non-negative integer.");
    }
    const outstandingBytes = state.localWindowMaximum - state.localWindow - state.acknowledgedLocalBytes;
    if (bytes > outstandingBytes) {
      throw new Error(`Channel ${localId} acknowledged more data than it received.`);
    }
    state.acknowledgedLocalBytes += bytes;
    return { ...state };
  }

  replenishAcknowledgedLocalWindow(localId: number): { state: ChannelState; bytesToAdd: number } {
    const state = this.require(localId);
    const bytesToAdd = state.acknowledgedLocalBytes;
    if (bytesToAdd > 0) {
      state.localWindow += bytesToAdd;
      state.acknowledgedLocalBytes = 0;
    }
    return { state: { ...state }, bytesToAdd };
  }

  markEofSent(localId: number): ChannelState {
    const state = this.require(localId);
    state.lifecycle = state.lifecycle === "eof-received" ? "closed" : "eof-sent";
    return { ...state };
  }

  markEofReceived(localId: number): ChannelState {
    const state = this.require(localId);
    state.lifecycle = state.lifecycle === "eof-sent" ? "closed" : "eof-received";
    return { ...state };
  }

  close(localId: number): ChannelState {
    const state = this.require(localId);
    state.lifecycle = "closed";
    this.channels.delete(localId);
    return { ...state };
  }

  get(localId: number): ChannelState | undefined {
    const state = this.channels.get(localId);
    return state ? { ...state } : undefined;
  }

  list(): ChannelState[] {
    return Array.from(this.channels.values(), (state) => ({ ...state }));
  }

  private requireCanSend(localId: number): ChannelState {
    const state = this.require(localId);
    if (state.lifecycle !== "open" && state.lifecycle !== "eof-received") {
      throw new Error(`Channel ${localId} is not open for sending.`);
    }
    return state;
  }

  private requireCanReceive(localId: number): ChannelState {
    const state = this.require(localId);
    if (state.lifecycle !== "open" && state.lifecycle !== "eof-sent") {
      throw new Error(`Channel ${localId} is not open for receiving.`);
    }
    return state;
  }

  private require(localId: number): ChannelState {
    const state = this.channels.get(localId);
    if (!state) {
      throw new Error(`Unknown channel ${localId}.`);
    }
    return state;
  }
}
