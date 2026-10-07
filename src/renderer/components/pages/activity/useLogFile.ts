import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../../api.js";
import { describeError } from "../../../lib/errors.js";
import type { LogFileInfo } from "../../../../shared/types.js";
import { firstNewLine, logReadFailure, parseLogContent, type LogRead } from "./activity-log.js";

export interface LogFileState {
  /** Last read result; undefined until the first read finishes. */
  read?: LogRead;
  /** When the last read finished (successfully or not). */
  readAt?: Date;
  reading: boolean;
  /** Lines from this index on are new since the previous read (they flash once). */
  newFrom: number;
  /** Increments per read so new-line highlights restart. */
  readNo: number;
  /** main.log and its archives on disk, from the last read (undefined when the sizes couldn't be read). */
  files?: LogFileInfo[];
}

export interface LogFileApi extends LogFileState {
  /** Reads main.log again; concurrent calls share one read. */
  refresh: () => Promise<LogRead | undefined>;
  /** Applies content the main process returned from another call (e.g. after clearing). */
  replace: (content: string) => void;
}

/**
 * main.log is not live: it is read when the Log file tab opens or on Refresh
 * (and once when the page opens, for the sizes the page shows).
 */
export function useLogFile(): LogFileApi {
  const [state, setState] = useState<LogFileState>({ reading: false, newFrom: 0, readNo: 0 });
  const inFlight = useRef<Promise<LogRead | undefined>>();
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const apply = useCallback((next: LogRead, files: LogFileInfo[] | undefined): void => {
    setState((current) => ({
      read: next,
      readAt: new Date(),
      reading: false,
      newFrom: firstNewLine(current.read, next),
      readNo: current.readNo + 1,
      files
    }));
  }, []);

  // Sizes are a bonus: a failure here leaves the page on what the read itself tells.
  const readFiles = useCallback(
    (): Promise<LogFileInfo[] | undefined> =>
      api.getLogFileInfo().then(
        (files) => (files.length > 0 ? files : undefined),
        () => undefined
      ),
    []
  );

  const refresh = useCallback((): Promise<LogRead | undefined> => {
    if (inFlight.current) {
      return inFlight.current;
    }
    setState((current) => ({ ...current, reading: true }));
    const read = api.readLogFile().then(
      (content) => parseLogContent(content),
      (error: unknown) => {
        const described = describeError(error, { title: "Couldn't read main.log" });
        return logReadFailure(described.message, described.technical);
      }
    );
    const promise = Promise.all([read, readFiles()])
      .then(([next, files]) => {
        if (mounted.current) {
          apply(next, files);
        }
        return next;
      })
      .finally(() => {
        inFlight.current = undefined;
      });
    inFlight.current = promise;
    return promise;
  }, [apply, readFiles]);

  const replace = useCallback(
    (content: string): void => {
      const next = parseLogContent(content);
      void readFiles().then((files) => {
        if (mounted.current) {
          apply(next, files);
        }
      });
    },
    [apply, readFiles]
  );

  return { ...state, refresh, replace };
}
