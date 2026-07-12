import { describe, expect, it, vi } from "vitest";
import { TransportMutationCoordinator } from "../src/main/app/transport-mutation-coordinator.js";

describe("TransportMutationCoordinator", () => {
  it("runs only the latest intent when multiple intents are queued", async () => {
    const coordinator = new TransportMutationCoordinator();
    const blocker = deferred<void>();
    const order: string[] = [];
    const queuedBlocker = coordinator.enqueue(() => blocker.promise);
    const first = coordinator.requestIntent(async () => {
      order.push("first");
    });
    const second = coordinator.requestIntent(async () => {
      order.push("second");
    });

    blocker.resolve(undefined);

    await expect(queuedBlocker).resolves.toBeUndefined();
    await expect(first).resolves.toBe(false);
    await expect(second).resolves.toBe(true);
    expect(order).toEqual(["second"]);
  });

  it("lets active work observe that a newer intent superseded it", async () => {
    const coordinator = new TransportMutationCoordinator();
    const started = deferred<void>();
    const resume = deferred<void>();
    const cleanup = vi.fn();
    const first = coordinator.requestIntent(async (generation) => {
      started.resolve(undefined);
      await resume.promise;
      if (!coordinator.isCurrent(generation)) {
        cleanup();
      }
    });
    await started.promise;
    const second = coordinator.requestIntent(async () => undefined);

    resume.resolve(undefined);

    await expect(first).resolves.toBe(false);
    await expect(second).resolves.toBe(true);
    expect(cleanup).toHaveBeenCalledOnce();
  });

  it("rejects a delayed startup intent when a user intent already exists", async () => {
    const coordinator = new TransportMutationCoordinator();
    const userIntent = coordinator.requestIntent(async () => undefined);
    const autoConnect = coordinator.requestIntent(async () => undefined, { expectedGeneration: 0 });

    await expect(userIntent).resolves.toBe(true);
    await expect(autoConnect).resolves.toBe(false);
    expect(coordinator.generation).toBe(1);
  });

  it("invalidates active intents on shutdown but still permits queued cleanup", async () => {
    const coordinator = new TransportMutationCoordinator();
    const started = deferred<void>();
    const resume = deferred<void>();
    const active = coordinator.requestIntent(async () => {
      started.resolve(undefined);
      await resume.promise;
    });
    await started.promise;

    coordinator.stopAcceptingIntents();
    const rejected = coordinator.requestIntent(async () => undefined);
    const cleanup = coordinator.enqueue(async () => "cleaned");
    resume.resolve(undefined);

    await expect(active).resolves.toBe(false);
    await expect(rejected).resolves.toBe(false);
    await expect(cleanup).resolves.toBe("cleaned");
  });

  it("keeps the serialization queue usable after an operation rejects", async () => {
    const coordinator = new TransportMutationCoordinator();
    await expect(
      coordinator.enqueue(async () => {
        throw new Error("failed");
      })
    ).rejects.toThrow("failed");

    await expect(coordinator.enqueue(async () => "next")).resolves.toBe("next");
  });
});

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}
