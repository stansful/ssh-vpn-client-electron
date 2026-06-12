import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("build assets", () => {
  it("has Windows and Linux package icons", () => {
    expect(existsSync("resources/icons/icon.ico")).toBe(true);
    expect(existsSync("resources/icons/icon.png")).toBe(true);
  });
});
