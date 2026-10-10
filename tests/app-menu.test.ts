import { describe, expect, it } from "vitest";
import { applicationMenuTemplate } from "../src/main/app/app-menu.js";

function roles(items: ReturnType<typeof applicationMenuTemplate>, index: number): unknown[] {
  const submenu = items?.[index]?.submenu;
  return Array.isArray(submenu) ? submenu.map((item) => item.role ?? item.type) : [];
}

describe("application menu", () => {
  it("gives macOS the Edit and Quit roles text fields and Cmd+Q rely on", () => {
    const menu = applicationMenuTemplate("darwin", "Shadow");
    expect(menu?.map((item) => item.role)).toEqual(["appMenu", "editMenu"]);
    expect(roles(menu, 0)).toEqual(["about", "separator", "hide", "hideOthers", "unhide", "separator", "quit"]);
    expect(roles(menu, 1)).toEqual(["undo", "redo", "separator", "cut", "copy", "paste", "selectAll"]);
  });

  it("labels the app items with the display name, not the system name app.name keeps", () => {
    const submenu = applicationMenuTemplate("darwin", "Shadow")?.[0]?.submenu;
    const labels = Array.isArray(submenu) ? submenu.map((item) => item.label).filter(Boolean) : [];
    expect(labels).toEqual(["About Shadow", "Hide Shadow", "Quit Shadow"]);
  });

  it("keeps Windows and Linux without a menu", () => {
    expect(applicationMenuTemplate("win32", "Shadow")).toBeNull();
    expect(applicationMenuTemplate("linux", "Shadow")).toBeNull();
  });
});
