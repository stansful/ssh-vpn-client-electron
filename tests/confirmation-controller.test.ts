import { describe, expect, it, vi } from "vitest";
import {
  AsyncConfirmationController,
  type ConfirmationViewState
} from "../src/renderer/lib/confirmation-controller.js";

interface Options {
  title: string;
  confirmLabel: string;
}

const deleteServer: Options = { title: "Delete Frankfurt-01?", confirmLabel: "Delete server" };

describe("async confirmation controller", () => {
  it("cancels without invoking the action and resolves false", async () => {
    const states: Array<ConfirmationViewState<Options> | undefined> = [];
    const action = vi.fn();
    const controller = new AsyncConfirmationController<Options>((state) => states.push(state));

    const result = controller.request(deleteServer, action);
    expect(controller.isOpen).toBe(true);
    expect(controller.cancel()).toBe(true);

    await expect(result).resolves.toBe(false);
    expect(action).not.toHaveBeenCalled();
    expect(states).toEqual([{ options: deleteServer, pending: false, error: undefined }, undefined]);
  });

  it("invokes the confirmed action exactly once and rejects overlapping work", async () => {
    const states: Array<ConfirmationViewState<Options> | undefined> = [];
    const actionDone = deferred<void>();
    const action = vi.fn(() => actionDone.promise);
    const controller = new AsyncConfirmationController<Options>((state) => states.push(state));

    const result = controller.request(deleteServer, action);
    const firstConfirmation = controller.confirm();

    expect(controller.cancel()).toBe(false);
    await expect(controller.request({ title: "Other?", confirmLabel: "Other" })).resolves.toBe(false);
    await expect(controller.confirm()).resolves.toBe(false);
    expect(action).toHaveBeenCalledOnce();
    expect(states.at(-1)).toMatchObject({ pending: true });

    actionDone.resolve();
    await expect(firstConfirmation).resolves.toBe(true);
    await expect(result).resolves.toBe(true);
    expect(action).toHaveBeenCalledOnce();
    expect(states.at(-1)).toBeUndefined();
    expect(controller.isOpen).toBe(false);
  });

  it("keeps the dialog open with the error when the action fails, and allows a retry", async () => {
    const states: Array<ConfirmationViewState<Options> | undefined> = [];
    const controller = new AsyncConfirmationController<Options>((state) => states.push(state));
    const error = new Error("delete failed");
    const action = vi.fn().mockRejectedValueOnce(error).mockResolvedValueOnce(undefined);

    const result = controller.request(deleteServer, action);

    await expect(controller.confirm()).resolves.toBe(false);
    expect(states.at(-1)).toEqual({ options: deleteServer, pending: false, error });
    expect(controller.isOpen).toBe(true);

    await expect(controller.confirm()).resolves.toBe(true);
    await expect(result).resolves.toBe(true);
    expect(states.at(-1)).toBeUndefined();
  });

  it("resolves true on confirm when there is no action", async () => {
    const controller = new AsyncConfirmationController<Options>(() => undefined);
    const result = controller.request(deleteServer);
    await expect(controller.confirm()).resolves.toBe(true);
    await expect(result).resolves.toBe(true);
  });
});

function deferred<T>(): { promise: Promise<T>; resolve: (value: T | PromiseLike<T>) => void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}
