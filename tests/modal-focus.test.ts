import { describe, expect, it } from "vitest";
import { ModalFocusStack, nextModalFocusIndex } from "../src/renderer/lib/modal-focus.js";

describe("modal focus navigation", () => {
  it("wraps forward and backward within the modal", () => {
    expect(nextModalFocusIndex(0, 3, false)).toBe(1);
    expect(nextModalFocusIndex(2, 3, false)).toBe(0);
    expect(nextModalFocusIndex(2, 3, true)).toBe(1);
    expect(nextModalFocusIndex(0, 3, true)).toBe(2);
  });

  it("recovers focus that starts outside the modal", () => {
    expect(nextModalFocusIndex(-1, 3, false)).toBe(0);
    expect(nextModalFocusIndex(-1, 3, true)).toBe(2);
  });

  it("handles an empty or invalid focus list safely", () => {
    expect(nextModalFocusIndex(-1, 0, false)).toBe(-1);
    expect(nextModalFocusIndex(0, Number.NaN, false)).toBe(-1);
  });

  it("lets only the topmost modal own the document focus trap", () => {
    const stack = new ModalFocusStack<symbol>();
    const lower = Symbol("lower");
    const upper = Symbol("upper");

    stack.activate(lower);
    expect(stack.isTopmost(lower)).toBe(true);

    stack.activate(upper);
    expect(stack.isTopmost(lower)).toBe(false);
    expect(stack.isTopmost(upper)).toBe(true);
    expect(stack.deactivate(lower)).toBe(false);
    expect(stack.isTopmost(upper)).toBe(true);
    expect(stack.deactivate(upper)).toBe(true);
    expect(stack.isTopmost(upper)).toBe(false);
  });
});
