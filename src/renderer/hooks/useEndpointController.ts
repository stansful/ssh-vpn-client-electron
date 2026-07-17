import { useState, type Dispatch, type FormEvent, type SetStateAction } from "react";
import { api } from "../api.js";
import { validateEndpointInput } from "../lib/endpoint.js";
import { toErrorMessage } from "../lib/labels.js";
import type { AppSettings, AppSnapshot } from "../../shared/types.js";

export function useEndpointController({
  settings,
  setSnapshot,
  setBusy
}: {
  settings: AppSettings;
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setBusy: (value: boolean) => void;
}) {
  const [endpointModalOpen, setEndpointModalOpen] = useState(false);
  const [endpointModalError, setEndpointModalError] = useState("");
  const [endpointDraft, setEndpointDraft] = useState("youtube.com:443");
  const [endpointSaving, setEndpointSaving] = useState(false);

  function openEndpointModal(): void {
    setEndpointDraft(settings.checkEndpoint);
    setEndpointModalError("");
    setEndpointModalOpen(true);
  }

  function saveEndpoint(event: FormEvent): void {
    event.preventDefault();
    const endpoint = endpointDraft.trim();
    const validation = validateEndpointInput(endpoint);
    if (!validation.ok) {
      setEndpointModalError(validation.message);
      return;
    }
    setEndpointSaving(true);
    setBusy(true);
    setEndpointModalError("");
    void api
      .updateSettings({ checkEndpoint: endpoint })
      .then((next) => {
        setSnapshot(next);
        setEndpointModalOpen(false);
      })
      .catch((error: unknown) => setEndpointModalError(toErrorMessage(error)))
      .finally(() => {
        setEndpointSaving(false);
        setBusy(false);
      });
  }

  function closeEndpointModal(): void {
    setEndpointModalOpen(false);
    setEndpointModalError("");
    setEndpointDraft(settings.checkEndpoint);
  }

  return {
    endpointModalOpen,
    endpointModalError,
    endpointDraft,
    endpointSaving,
    setEndpointDraft,
    openEndpointModal,
    closeEndpointModal,
    saveEndpoint
  };
}
