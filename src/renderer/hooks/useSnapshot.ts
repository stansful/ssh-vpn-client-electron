import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import { api } from "../api.js";
import { applyServiceEventToSnapshot } from "../lib/diagnostics.js";
import { toErrorMessage } from "../lib/labels.js";
import type { AppSnapshot } from "../../shared/types.js";

export function useSnapshot(): {
  snapshot: AppSnapshot | undefined;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  notice: string;
  setNotice: Dispatch<SetStateAction<string>>;
} {
  const [snapshot, setSnapshot] = useState<AppSnapshot | undefined>();
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    api
      .loadSnapshot()
      .then((loaded) => {
        if (active) {
          setSnapshot(loaded);
        }
      })
      .catch((error: unknown) => setNotice(toErrorMessage(error)));

    const off = api.onServiceEvent((event) => {
      if (!active) {
        return;
      }
      setSnapshot((current) => applyServiceEventToSnapshot(current, event));
      if (event.type === "error") {
        setNotice(event.message);
      }
    });

    return () => {
      active = false;
      off();
    };
  }, []);

  return { snapshot, setSnapshot, notice, setNotice };
}
