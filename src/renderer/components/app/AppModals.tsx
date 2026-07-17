import { ConfigForm } from "../forms/ConfigForm.js";
import { EndpointForm } from "../forms/EndpointForm.js";
import { KeyForm } from "../forms/KeyForm.js";
import { Modal } from "../ui/index.js";
import type { useEndpointController } from "../../hooks/useEndpointController.js";
import type { useSshEntitiesController } from "../../hooks/useSshEntitiesController.js";
import type { AppSnapshot } from "../../../shared/types.js";

export function AppModals({
  store,
  ssh,
  endpoint
}: {
  store: AppSnapshot["store"];
  ssh: ReturnType<typeof useSshEntitiesController>;
  endpoint: ReturnType<typeof useEndpointController>;
}): JSX.Element {
  return (
    <>
      <Modal
        open={ssh.configModalOpen}
        title={ssh.configDraft.mode === "edit" ? "Edit SSH configuration" : "Add SSH configuration"}
        onClose={ssh.closeConfigModal}
        closeDisabled={ssh.configSaving}
      >
        <ConfigForm
          draft={ssh.configDraft}
          error={ssh.configModalError}
          keys={store.sshKeys}
          busy={ssh.configSaving}
          onChange={ssh.setConfigDraft}
          onSubmit={ssh.saveConfig}
          onCancel={ssh.closeConfigModal}
        />
      </Modal>

      <Modal
        open={ssh.keyModalOpen}
        title={ssh.keyDraft.mode === "edit" ? "Edit SSH key" : "Add SSH key"}
        onClose={ssh.closeKeyModal}
        closeDisabled={ssh.keySaving}
      >
        <KeyForm
          draft={ssh.keyDraft}
          error={ssh.keyModalError}
          busy={ssh.keySaving}
          onChange={ssh.setKeyDraft}
          onSubmit={ssh.saveKey}
          onCancel={ssh.closeKeyModal}
          onCopySavedPrivateKey={ssh.copySavedPrivateKey}
        />
      </Modal>

      <Modal open={endpoint.endpointModalOpen} title="Edit tunnel check endpoint" onClose={endpoint.closeEndpointModal} closeDisabled={endpoint.endpointSaving}>
        <EndpointForm
          value={endpoint.endpointDraft}
          error={endpoint.endpointModalError}
          busy={endpoint.endpointSaving}
          onChange={endpoint.setEndpointDraft}
          onSubmit={endpoint.saveEndpoint}
          onCancel={endpoint.closeEndpointModal}
        />
      </Modal>
    </>
  );
}
