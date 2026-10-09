import type { MenuItemConstructorOptions } from "electron";

/**
 * The OS application menu. Windows and Linux get none (the window has no menu
 * bar). macOS needs one: Cmd+C/V/X/A/Z in text fields and Cmd+Q only work
 * through the menu's Edit and Quit roles. Quit goes through app.quit(), so it
 * runs the same shutdown as the tray's Quit.
 */
export function applicationMenuTemplate(platform: NodeJS.Platform): MenuItemConstructorOptions[] | null {
  if (platform !== "darwin") {
    return null;
  }
  return [
    {
      role: "appMenu",
      submenu: [{ role: "about" }, { type: "separator" }, { role: "hide" }, { role: "hideOthers" }, { role: "unhide" }, { type: "separator" }, { role: "quit" }]
    },
    {
      role: "editMenu",
      submenu: [{ role: "undo" }, { role: "redo" }, { type: "separator" }, { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" }]
    }
  ];
}
