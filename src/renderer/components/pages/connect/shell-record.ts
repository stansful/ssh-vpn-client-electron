import type { ShellRecord } from "./terminal-view.js";

/**
 * What happens to the panel's shell: an open request and its answer, or a
 * collapse. The main process runs open and close requests in order, so a
 * collapse and re-expand during an open simply queues open, close, open.
 */
export type ShellRecordEvent =
  | { type: "open"; session: string; attempt: number; afterId?: string }
  | { type: "opened"; session: string; attempt: number }
  | { type: "open-failed"; session: string; attempt: number; error: string }
  | { type: "close" };

/**
 * The next record. An answer counts only for the open request the record is
 * still waiting on: after a collapse, or a newer request, the older answer
 * would mark the wrong shell as open (or leave the panel waiting forever).
 */
export function nextShellRecord(current: ShellRecord | undefined, event: ShellRecordEvent): ShellRecord | undefined {
  if (event.type === "open") {
    return { session: event.session, phase: "opening", attempt: event.attempt, afterId: event.afterId };
  }
  if (event.type === "close") {
    return undefined;
  }
  if (current?.session !== event.session || current.attempt !== event.attempt || current.phase !== "opening") {
    return current;
  }
  return event.type === "opened" ? { ...current, phase: "open" } : { ...current, phase: "failed", error: event.error };
}

/** An open for this session is already on its way and nothing has replaced it, so asking again would only repeat it. */
export function isOpenPending(record: ShellRecord | undefined, session: string): boolean {
  return record?.session === session && record.phase === "opening";
}

/** Collapsing must close a shell that is open or still opening; a failed open left nothing to close. */
export function shellNeedsClose(record: ShellRecord | undefined, session: string): boolean {
  return record?.session === session && record.phase !== "failed";
}
