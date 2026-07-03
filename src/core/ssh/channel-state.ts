export type ChannelLifecycle = "opening" | "open" | "eof-sent" | "eof-received" | "closed";

export interface ChannelState {
  localId: number;
  remoteId?: number;
  kind: "session" | "direct-tcpip";
  lifecycle: ChannelLifecycle;
  localWindow: number;
  localWindowMaximum: number;
  remoteWindow: number;
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
      remoteWindow: 0,
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
    state.remoteId = remoteId;
    state.remoteWindow = remoteWindow;
    state.maximumPacketSize = maximumPacketSize;
    state.lifecycle = "open";
    return { ...state };
  }

  consumeRemoteWindow(localId: number, bytes: number): ChannelState {
    const state = this.requireOpen(localId);
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
    state.remoteWindow += bytes;
    return { ...state };
  }

  consumeLocalWindow(localId: number, bytes: number): ChannelState {
    const state = this.requireOpen(localId);
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
    const state = this.requireOpen(localId);
    if (bytes < 0 || !Number.isInteger(bytes)) {
      throw new Error("Window bytes must be a non-negative integer.");
    }
    state.localWindow += bytes;
    return { ...state };
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

  private requireOpen(localId: number): ChannelState {
    const state = this.require(localId);
    if (state.lifecycle !== "open") {
      throw new Error(`Channel ${localId} is not open.`);
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
