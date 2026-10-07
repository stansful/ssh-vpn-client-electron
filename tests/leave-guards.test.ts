import { describe, expect, it, vi } from "vitest";
import { LeaveGuards } from "../src/renderer/lib/leave-guards.js";

describe("leave guards", () => {
  it("lets navigation through when nothing is guarded", async () => {
    const guards = new LeaveGuards();
    expect(guards.isEmpty).toBe(true);
    await expect(guards.confirmLeave()).resolves.toBe(true);
  });

  it("stays when a form with unsaved changes says Keep editing", async () => {
    const guards = new LeaveGuards();
    const keepEditing = vi.fn(async () => false);
    guards.add(keepEditing);

    await expect(guards.confirmLeave()).resolves.toBe(false);
    expect(keepEditing).toHaveBeenCalledOnce();
  });

  it("asks the form on top first and stops at the first that stays", async () => {
    const guards = new LeaveGuards();
    const asked: string[] = [];
    guards.add(async () => {
      asked.push("server form");
      return true;
    });
    guards.add(async () => {
      asked.push("key form");
      return false;
    });

    await expect(guards.confirmLeave()).resolves.toBe(false);
    expect(asked).toEqual(["key form"]);
  });

  it("treats a failing guard as stay, and forgets removed guards", async () => {
    const guards = new LeaveGuards();
    const remove = guards.add(async () => {
      throw new Error("dialog already open");
    });
    await expect(guards.confirmLeave()).resolves.toBe(false);

    remove();
    expect(guards.isEmpty).toBe(true);
    await expect(guards.confirmLeave()).resolves.toBe(true);
  });
});
