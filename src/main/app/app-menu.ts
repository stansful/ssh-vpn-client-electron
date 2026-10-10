import type { MenuItemConstructorOptions } from "electron";

/**
 * The OS application menu. Windows and Linux get none (the window has no menu
 * bar). macOS needs one: Cmd+C/V/X/A/Z in text fields and Cmd+Q only work
 * through the menu's Edit and Quit roles. Quit goes through app.quit(), so it
 * runs the same shutdown as the tray's Quit.
 */
export function applicationMenuTemplate(platform: NodeJS.Platform, appName: string): MenuItemConstructorOptions[] | null {
  if (platform !== "darwin") {
    return null;
  }
  // The roles would label these with app.name, which stays the pre-rename
  // system name; the menu bar itself shows the bundle name.
  return [
    {
      role: "appMenu",
      submenu: [
        { role: "about", label: `About ${appName}` },
        { type: "separator" },
        { role: "hide", label: `Hide ${appName}` },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit", label: `Quit ${appName}` }
      ]
    },
    {
      role: "editMenu",
      submenu: [{ role: "undo" }, { role: "redo" }, { type: "separator" }, { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" }]
    }
  ];
}
