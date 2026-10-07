import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { describeError } from "../../lib/errors.js";
import { useToasts } from "../../hooks/useToasts.js";

/** The main process refuses clipboard text above this many characters. */
export const CLIPBOARD_TEXT_LIMIT = 2_097_152;
const COPIED_FLASH_MS = 1600;

/**
 * Copy with the shared feedback rules: `copied` flashes true for 1.6 s on
 * success; failures (including the size limit) show an error toast.
 */
export function useCopyFeedback(): { copied: boolean; copy: (text: string) => Promise<boolean> } {
  const { toast } = useToasts();
  const [copied, setCopied] = useState(false);
  const timer = useRef<number>();

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = useCallback(async (text: string): Promise<boolean> => {
    const ok = await copyTextWithFeedback(text, toast);
    if (ok) {
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), COPIED_FLASH_MS);
    }
    return ok;
  }, [toast]);

  return { copied, copy };
}

/** Copies text; reports failures as an error toast. Resolves true when copied. */
export async function copyTextWithFeedback(
  text: string,
  toast: ReturnType<typeof useToasts>["toast"]
): Promise<boolean> {
  if (text.length > CLIPBOARD_TEXT_LIMIT) {
    toast({
      id: "copy-failed",
      tone: "error",
      title: "Couldn't copy",
      message: "The text is over the 2,097,152-character clipboard limit. Copy a shorter part instead."
    });
    return false;
  }
  try {
    const ok = await api.copyText(text);
    if (!ok) {
      toast({ id: "copy-failed", tone: "error", title: "Couldn't copy", message: "The clipboard didn't accept the text. Try again." });
    }
    return ok;
  } catch (error) {
    const described = describeError(error, { title: "Couldn't copy" });
    toast({ id: "copy-failed", tone: "error", title: described.title, message: described.message, details: described.technical });
    return false;
  }
}

/**
 * Reads plain text from the clipboard for explicit Paste buttons (works even
 * where keyboard shortcuts don't). Resolves undefined and shows a toast when
 * there is nothing to paste.
 */
export function usePasteFromClipboard(): () => Promise<string | undefined> {
  const { toast } = useToasts();
  return useCallback(async (): Promise<string | undefined> => {
    try {
      const text = await api.readClipboardText();
      if (!text) {
        toast({ id: "paste-empty", tone: "info", title: "Nothing to paste", message: "The clipboard is empty or doesn't hold text." });
        return undefined;
      }
      return text;
    } catch (error) {
      const described = describeError(error, { title: "Couldn't paste" });
      toast({ id: "paste-failed", tone: "error", title: described.title, message: described.message, details: described.technical });
      return undefined;
    }
  }, [toast]);
}
