/**
 * How long quitting waits for the tunnels to shut down. Disposal queues
 * behind whatever transport change is running, and a connect can take minutes
 * to give up; the user asked to quit, so after this the app exits anyway.
 */
export const QUIT_DEADLINE_MS = 10_000;

export interface QuitDeadlineOptions {
  deadlineMs?: number;
  setTimer?: (callback: () => void, ms: number) => unknown;
  clearTimer?: (timer: unknown) => void;
}

/**
 * Settles with "completed" once `work` settles (fulfilled or rejected - the
 * cleanup reports its own failures), or with "deadline" when it is still
 * running after the deadline. Never rejects.
 */
export function settleBeforeDeadline(work: Promise<unknown>, options: QuitDeadlineOptions = {}): Promise<"completed" | "deadline"> {
  const deadlineMs = options.deadlineMs ?? QUIT_DEADLINE_MS;
  const setTimer = options.setTimer ?? ((callback: () => void, ms: number) => setTimeout(callback, ms));
  const clearTimer = options.clearTimer ?? ((timer: unknown) => clearTimeout(timer as NodeJS.Timeout));
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimer(() => {
      if (!settled) {
        settled = true;
        resolve("deadline");
      }
    }, deadlineMs);
    const finish = (): void => {
      if (!settled) {
        settled = true;
        clearTimer(timer);
        resolve("completed");
      }
    };
    work.then(finish, finish);
  });
}
