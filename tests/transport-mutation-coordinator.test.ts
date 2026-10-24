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

  it("runs an intent's preempt at once, ahead of the work it is queued behind", async () => {
    const coordinator = new TransportMutationCoordinator();
    const blocker = deferred<void>();
    const order: string[] = [];
    const busy = coordinator.enqueue(async () => {
      await blocker.promise;
      order.push("work ahead");
    });
    const intent = coordinator.requestIntent(
      async () => {
        order.push("intent");
      },
      { preempt: () => order.push("preempt") }
    );
    expect(order).toEqual(["preempt"]);

    blocker.resolve(undefined);
    await busy;
    await expect(intent).resolves.toBe(true);
    expect(order).toEqual(["preempt", "work ahead", "intent"]);
  });

  it("skips the preempt of an intent it does not accept, and runs the intent when the preempt throws", async () => {
    const coordinator = new TransportMutationCoordinator();
    const preempt = vi.fn();
    await coordinator.requestIntent(async () => undefined);
    await expect(coordinator.requestIntent(async () => undefined, { expectedGeneration: 0, preempt })).resolves.toBe(false);
    expect(preempt).not.toHaveBeenCalled();

    const operation = vi.fn(async () => undefined);
    await expect(
      coordinator.requestIntent(operation, {
        preempt: () => {
          throw new Error("no session");
        }
      })
    ).resolves.toBe(true);
    expect(operation).toHaveBeenCalledOnce();

    coordinator.stopAcceptingIntents();
    await expect(coordinator.requestIntent(async () => undefined, { preempt })).resolves.toBe(false);
    expect(preempt).not.toHaveBeenCalled();
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
