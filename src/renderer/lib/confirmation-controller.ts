export interface ConfirmationRequest {
  title: string;
  message: string;
  confirmLabel?: string;
  pendingLabel?: string;
  onConfirm: () => void | Promise<void>;
}

export interface ConfirmationViewState {
  title: string;
  message: string;
  confirmLabel: string;
  pendingLabel: string;
  pending: boolean;
}

interface ActiveConfirmation {
  request: ConfirmationRequest;
  pending: boolean;
}

/**
 * Owns one application-level confirmation at a time. The synchronous pending
 * guard is intentionally separate from React state so rapid double-clicks
 * cannot run a destructive action twice before the button rerenders.
 */
export class AsyncConfirmationController {
  private active: ActiveConfirmation | undefined;

  constructor(private readonly publish: (state: ConfirmationViewState | undefined) => void) {}

  request(request: ConfirmationRequest): boolean {
    if (this.active) {
      return false;
    }
    this.active = { request, pending: false };
    this.publishState();
    return true;
  }

  cancel(): boolean {
    if (!this.active || this.active.pending) {
      return false;
    }
    this.active = undefined;
    this.publish(undefined);
    return true;
  }

  async confirm(): Promise<boolean> {
    const active = this.active;
    if (!active || active.pending) {
      return false;
    }

    active.pending = true;
    this.publishState();
    try {
      await active.request.onConfirm();
      return true;
    } finally {
      if (this.active === active) {
        this.active = undefined;
        this.publish(undefined);
      }
    }
  }

  private publishState(): void {
    const active = this.active;
    if (!active) {
      this.publish(undefined);
      return;
    }
    this.publish({
      title: active.request.title,
      message: active.request.message,
      confirmLabel: active.request.confirmLabel ?? "Confirm",
      pendingLabel: active.request.pendingLabel ?? "Working...",
      pending: active.pending
    });
  }
}
