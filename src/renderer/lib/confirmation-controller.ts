export interface ConfirmationViewState<TOptions> {
  options: TOptions;
  /** The confirmed action is running; Cancel, Esc and the scrim wait. */
  pending: boolean;
  /** The last attempt failed; the dialog stays open so the user can retry or cancel. */
  error?: unknown;
}

interface ActiveConfirmation<TOptions> {
  options: TOptions;
  onConfirm?: () => void | Promise<void>;
  resolve: (confirmed: boolean) => void;
  pending: boolean;
  error?: unknown;
}

/**
 * Owns one application-level confirmation at a time. The synchronous pending
 * guard is intentionally separate from React state so rapid double-clicks
 * cannot run a destructive action twice before the button rerenders.
 */
export class AsyncConfirmationController<TOptions> {
  private active: ActiveConfirmation<TOptions> | undefined;

  constructor(private readonly publish: (state: ConfirmationViewState<TOptions> | undefined) => void) {}

  /**
   * Opens a confirmation. Resolves `true` once the action ran (or, without an
   * action, once the user confirmed) and `false` when cancelled or when another
   * confirmation is already open.
   */
  request(options: TOptions, onConfirm?: () => void | Promise<void>): Promise<boolean> {
    if (this.active) {
      return Promise.resolve(false);
    }
    return new Promise<boolean>((resolve) => {
      this.active = { options, onConfirm, resolve, pending: false };
      this.publishState();
    });
  }

  get isOpen(): boolean {
    return this.active !== undefined;
  }

  cancel(): boolean {
    const active = this.active;
    if (!active || active.pending) {
      return false;
    }
    this.active = undefined;
    this.publish(undefined);
    active.resolve(false);
    return true;
  }

  async confirm(): Promise<boolean> {
    const active = this.active;
    if (!active || active.pending) {
      return false;
    }

    active.pending = true;
    active.error = undefined;
    this.publishState();
    try {
      await active.onConfirm?.();
    } catch (error) {
      if (this.active === active) {
        active.pending = false;
        active.error = error;
        this.publishState();
      }
      return false;
    }
    if (this.active === active) {
      this.active = undefined;
      this.publish(undefined);
    }
    active.resolve(true);
    return true;
  }

  private publishState(): void {
    const active = this.active;
    if (!active) {
      this.publish(undefined);
      return;
    }
    this.publish({ options: active.options, pending: active.pending, error: active.error });
  }
}
