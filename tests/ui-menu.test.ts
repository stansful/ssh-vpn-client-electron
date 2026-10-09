import { describe, expect, it } from "vitest";
import { placeActionMenu, typeaheadIndex } from "../src/renderer/components/ui/Menu.js";

const viewport = { width: 1000, height: 700 };
const menu = { width: 220, height: 130 };

describe("action menu placement", () => {
  it("opens under the anchor with the right edges aligned", () => {
    expect(placeActionMenu(menu, viewport, { anchor: { top: 100, right: 600, bottom: 132 } })).toEqual({ left: 380, top: 138, side: "bottom" });
  });

  it("flips above the anchor near the bottom of the window", () => {
    expect(placeActionMenu(menu, viewport, { anchor: { top: 600, right: 600, bottom: 632 } })).toEqual({ left: 380, top: 464, side: "top" });
  });

  it("stays below, shifted up to fit, when there is even less room above", () => {
    const tall = { width: 220, height: 400 };
    expect(placeActionMenu(tall, viewport, { anchor: { top: 300, right: 600, bottom: 332 } })).toMatchObject({ top: 288, side: "bottom" });
  });

  it("keeps 12 px inside the viewport", () => {
    expect(placeActionMenu(menu, viewport, { anchor: { top: 100, right: 150, bottom: 132 } }).left).toBe(12);
    expect(placeActionMenu(menu, viewport, { anchor: { top: 100, right: 1200, bottom: 132 } }).left).toBe(768);
  });

  it("puts the top-left corner at the pointer and flips up when it doesn't fit", () => {
    expect(placeActionMenu(menu, viewport, { point: { x: 300, y: 200 } })).toEqual({ left: 300, top: 200, side: "bottom" });
    expect(placeActionMenu(menu, viewport, { point: { x: 300, y: 650 } })).toEqual({ left: 300, top: 520, side: "top" });
    expect(placeActionMenu(menu, viewport, { point: { x: 950, y: 200 } }).left).toBe(768);
  });

  it("pins an oversized menu to the top-left margin", () => {
    expect(placeActionMenu({ width: 1200, height: 900 }, viewport, { point: { x: 500, y: 300 } })).toMatchObject({ left: 12, top: 12 });
  });
});

describe("action menu type-ahead", () => {
  const labels = ["Rename", "Copy link", "Remove"];

  it("cycles through items that start with the letter", () => {
    expect(typeaheadIndex(labels, 0, "r")).toBe(2);
    expect(typeaheadIndex(labels, 2, "R")).toBe(0);
    expect(typeaheadIndex(labels, 0, "c")).toBe(1);
  });

  it("starts from the top when nothing is focused", () => {
    expect(typeaheadIndex(labels, -1, "r")).toBe(0);
  });

  it("stays on the only match and reports no match", () => {
    expect(typeaheadIndex(labels, 1, "c")).toBe(1);
    expect(typeaheadIndex(labels, 0, "x")).toBe(-1);
    expect(typeaheadIndex([], -1, "r")).toBe(-1);
  });
});
