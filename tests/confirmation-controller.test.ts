import { describe, expect, it, vi } from "vitest";
import {
  AsyncConfirmationController,
  type ConfirmationViewState
} from "../src/renderer/lib/confirmation-controller.js";

describe("async confirmation controller", () => {
  it("cancels without invoking the action", () => {
    const states: Array<ConfirmationViewState | undefined> = [];
    const action = vi.fn();
    const controller = new AsyncConfirmationController((state) => states.push(state));

    expect(controller.request({ title: "Delete", message: "Delete it?", onConfirm: action })).toBe(true);
    expect(controller.cancel()).toBe(true);

    expect(action).not.toHaveBeenCalled();
    expect(states).toEqual([
      {
        title: "Delete",
        message: "Delete it?",
        confirmLabel: "Confirm",
        pendingLabel: "Working...",
        pending: false
      },
      undefined
    ]);
  });

  it("invokes the confirmed action exactly once and rejects overlapping work", async () => {
    const states: Array<ConfirmationViewState | undefined> = [];
    const actionDone = deferred<void>();
    const action = vi.fn(() => actionDone.promise);
    const controller = new AsyncConfirmationController((state) => states.push(state));

    expect(controller.request({
      title: "Delete",
      message: "Delete it?",
      confirmLabel: "Delete",
      pendingLabel: "Deleting...",
      onConfirm: action
    })).toBe(true);

    const firstConfirmation = controller.confirm();
    expect(controller.cancel()).toBe(false);
    expect(controller.request({ title: "Other", message: "Other?", onConfirm: vi.fn() })).toBe(false);
    await expect(controller.confirm()).resolves.toBe(false);
    expect(action).toHaveBeenCalledOnce();
    expect(states.at(-1)).toMatchObject({ pending: true, pendingLabel: "Deleting..." });

    actionDone.resolve();
    await expect(firstConfirmation).resolves.toBe(true);
    expect(action).toHaveBeenCalledOnce();
    expect(states.at(-1)).toBeUndefined();
  });

  it("clears pending state while preserving action errors for the existing caller", async () => {
    const states: Array<ConfirmationViewState | undefined> = [];
    const controller = new AsyncConfirmationController((state) => states.push(state));
    const error = new Error("delete failed");

    controller.request({
      title: "Delete",
      message: "Delete it?",
      onConfirm: () => Promise.reject(error)
    });

    await expect(controller.confirm()).rejects.toBe(error);
    expect(states.at(-1)).toBeUndefined();
  });
});

function deferred<T>(): { promise: Promise<T>; resolve: (value: T | PromiseLike<T>) => void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}
