import { useState, type Dispatch, type FormEvent, type SetStateAction } from "react";
import { api } from "../api.js";
import { toErrorMessage } from "../lib/labels.js";
import { emptyConfigDraft, emptyKeyDraft, type ConfigDraft, type KeyDraft, type View } from "../types.js";
import type { AppSnapshot, SshConfig, SshKeyMetadata, UpsertSshKeyInput } from "../../shared/types.js";

export function useSshEntitiesController({
  setSnapshot,
  setBusy,
  setView
}: {
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setView: Dispatch<SetStateAction<View>>;
}) {
  const [configDraft, setConfigDraft] = useState<ConfigDraft>(emptyConfigDraft);
  const [keyDraft, setKeyDraft] = useState<KeyDraft>(emptyKeyDraft);
  const [configModalOpen, setConfigModalOpen] = useState(false);
  const [keyModalOpen, setKeyModalOpen] = useState(false);
  const [configModalError, setConfigModalError] = useState("");
  const [keyModalError, setKeyModalError] = useState("");

  function editConfig(config: SshConfig): void {
    setConfigModalError("");
    setConfigDraft({
      mode: "edit",
      id: config.id,
      name: config.name,
      host: config.host,
      port: config.port,
      username: config.username,
      authType: config.authType,
      password: "",
      privateKeyId: config.privateKeyId ?? "",
      expectedServerFingerprint: config.expectedServerFingerprint,
      keepaliveIntervalSec: config.keepaliveIntervalSec,
      note: config.note
    });
    setView("configs");
    setConfigModalOpen(true);
  }

  function saveConfig(event: FormEvent): void {
    event.preventDefault();
    setBusy(true);
    setConfigModalError("");
    void api
      .upsertConfig({
        ...configDraft,
        privateKeyId: configDraft.privateKeyId || undefined,
        password: configDraft.password || undefined
      })
      .then((next) => {
        setSnapshot(next);
        setConfigDraft(emptyConfigDraft());
        setConfigModalOpen(false);
      })
      .catch((error: unknown) => setConfigModalError(toErrorMessage(error)))
      .finally(() => setBusy(false));
  }

  function openKeyModal(draft: KeyDraft): void {
    setKeyModalError("");
    setKeyDraft(draft);
    setKeyModalOpen(true);
  }

  function openConfigModal(draft: ConfigDraft): void {
    setConfigModalError("");
    setConfigDraft(draft);
    setConfigModalOpen(true);
  }

  function closeConfigModal(): void {
    setConfigModalOpen(false);
    setConfigDraft(emptyConfigDraft());
    setConfigModalError("");
  }

  function closeKeyModal(): void {
    setKeyModalOpen(false);
    setKeyDraft(emptyKeyDraft());
    setKeyModalError("");
  }

  function editKey(key: SshKeyMetadata): void {
    openKeyModal({
      mode: "edit",
      id: key.id,
      name: key.name,
      privateKey: "",
      privateKeyPassphrase: ""
    });
    setView("keys");
  }

  function saveKey(event: FormEvent): void {
    event.preventDefault();
    setBusy(true);
    setKeyModalError("");
    const payload: UpsertSshKeyInput = {
      id: keyDraft.id,
      name: keyDraft.name,
      privateKey: keyDraft.privateKey || undefined,
      privateKeyPassphrase: keyDraft.privateKeyPassphrase || undefined
    };
    void api
      .upsertKey(payload)
      .then((next) => {
        setSnapshot(next);
        setKeyDraft(emptyKeyDraft());
        setKeyModalOpen(false);
      })
      .catch((error: unknown) => setKeyModalError(toErrorMessage(error)))
      .finally(() => setBusy(false));
  }

  function copySavedPrivateKey(id: string | undefined): void {
    if (!id) {
      setKeyModalError("Save the SSH key before copying the stored private key.");
      return;
    }
    setKeyModalError("");
    void api
      .copyPrivateKey(id)
      .then(() => setKeyModalError("Saved private key copied to clipboard."))
      .catch((error: unknown) => setKeyModalError(toErrorMessage(error)));
  }

  return {
    configDraft,
    setConfigDraft,
    keyDraft,
    setKeyDraft,
    configModalOpen,
    keyModalOpen,
    configModalError,
    keyModalError,
    openConfigModal,
    closeConfigModal,
    openKeyModal,
    closeKeyModal,
    editConfig,
    saveConfig,
    editKey,
    saveKey,
    copySavedPrivateKey
  };
}
