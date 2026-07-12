export interface TransportIntentOptions {
  expectedGeneration?: number;
}

/**
 * Serializes cross-transport mutations while allowing a newer user intent to
 * supersede work that is queued or currently awaiting an external operation.
 */
export class TransportMutationCoordinator {
  private tail: Promise<void> = Promise.resolve();
  private currentGeneration = 0;
  private stopping = false;

  get generation(): number {
    return this.currentGeneration;
  }

  get isStopping(): boolean {
    return this.stopping;
  }

  isCurrent(generation: number): boolean {
    return !this.stopping && generation === this.currentGeneration;
  }

  enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation);
    this.tail = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  requestIntent(
    operation: (generation: number) => Promise<void>,
    options: TransportIntentOptions = {}
  ): Promise<boolean> {
    if (
      this.stopping ||
      (options.expectedGeneration !== undefined && options.expectedGeneration !== this.currentGeneration)
    ) {
      return Promise.resolve(false);
    }

    const generation = ++this.currentGeneration;
    return this.enqueue(async () => {
      if (!this.isCurrent(generation)) {
        return false;
      }
      await operation(generation);
      return this.isCurrent(generation);
    });
  }

  stopAcceptingIntents(): void {
    if (this.stopping) {
      return;
    }
    this.stopping = true;
    this.currentGeneration += 1;
  }
}
