import type { RoutingRule } from "../../../../shared/types.js";
import { EXPORT_FILE_NAME, serializeRules } from "./rule-import.js";

interface SaveFileHandle {
  name: string;
  createWritable(): Promise<{ write(data: Blob): Promise<void>; close(): Promise<void> }>;
}

interface SaveFilePickerWindow {
  showSaveFilePicker?: (options: {
    suggestedName: string;
    types: Array<{ description: string; accept: Record<string, string[]> }>;
  }) => Promise<SaveFileHandle>;
}

export type ExportOutcome = { saved: true; fileName: string } | { saved: false };

/**
 * Saves the rules as JSON. The native save picker tells us whether the file
 * was written (and under which name), so a cancel shows nothing; where the
 * picker is unavailable it falls back to a regular download.
 */
export async function exportRulesToFile(rules: readonly RoutingRule[]): Promise<ExportOutcome> {
  const blob = new Blob([serializeRules(rules)], { type: "application/json" });
  const picker = (window as unknown as SaveFilePickerWindow).showSaveFilePicker;
  if (picker) {
    let handle: SaveFileHandle;
    try {
      handle = await picker.call(window, {
        suggestedName: EXPORT_FILE_NAME,
        types: [{ description: "Routing rules", accept: { "application/json": [".json"] } }]
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        return { saved: false };
      }
      return downloadBlob(blob);
    }
    const writable = await handle.createWritable();
    await writable.write(blob);
    await writable.close();
    return { saved: true, fileName: handle.name };
  }
  return downloadBlob(blob);
}

function downloadBlob(blob: Blob): ExportOutcome {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = EXPORT_FILE_NAME;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
  return { saved: true, fileName: EXPORT_FILE_NAME };
}
