/** Asks whether the current page may be left; resolves false to stay. */
export type LeaveGuard = () => Promise<boolean>;

/**
 * Checks that run before navigation. A form with unsaved changes registers
 * one, because some navigation never goes through its own Close: a toast's
 * "Open Connect" sits above the modal scrim, and following it would unmount
 * the form with the edits in it.
 */
export class LeaveGuards {
  private readonly guards: LeaveGuard[] = [];

  /** Returns the function that removes it again. */
  add(guard: LeaveGuard): () => void {
    this.guards.push(guard);
    return () => {
      const index = this.guards.lastIndexOf(guard);
      if (index >= 0) {
        this.guards.splice(index, 1);
      }
    };
  }

  get isEmpty(): boolean {
    return this.guards.length === 0;
  }

  /** Asks the newest guard first (the form on top) and stops at the first that wants to stay. */
  async confirmLeave(): Promise<boolean> {
    for (const guard of [...this.guards].reverse()) {
      let leave = false;
      try {
        leave = await guard();
      } catch {
        leave = false;
      }
      if (!leave) {
        return false;
      }
    }
    return true;
  }
}
