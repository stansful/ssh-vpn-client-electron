import { useCallback, useRef, useState } from "react";
import {
  AsyncConfirmationController,
  type ConfirmationRequest,
  type ConfirmationViewState
} from "../lib/confirmation-controller.js";

export function useConfirmationController(): {
  state: ConfirmationViewState | undefined;
  request: (request: ConfirmationRequest) => boolean;
  cancel: () => boolean;
  confirm: () => Promise<boolean>;
} {
  const [state, setState] = useState<ConfirmationViewState>();
  const controllerRef = useRef<AsyncConfirmationController>();
  if (!controllerRef.current) {
    controllerRef.current = new AsyncConfirmationController(setState);
  }

  const request = useCallback(
    (next: ConfirmationRequest): boolean => controllerRef.current!.request(next),
    []
  );
  const cancel = useCallback((): boolean => controllerRef.current!.cancel(), []);
  const confirm = useCallback((): Promise<boolean> => controllerRef.current!.confirm(), []);

  return { state, request, cancel, confirm };
}
