import type { Dispatch, SetStateAction } from "react";
import { api } from "../api.js";
import { toErrorMessage } from "../lib/labels.js";
import type { AppSettings, AppSnapshot, ImportProxyProfilesInput, UpsertProxyProfileInput } from "../../shared/types.js";

export function useXrayController({
  setSnapshot,
  setNotice,
  updateSettings,
  commitSnapshotAction,
  setBusy
}: {
  setSnapshot: Dispatch<SetStateAction<AppSnapshot | undefined>>;
  setNotice: Dispatch<SetStateAction<string>>;
  updateSettings: (patch: Partial<AppSettings>) => void;
  commitSnapshotAction: (action: () => Promise<AppSnapshot>, successMessage?: string) => Promise<void>;
  setBusy: (value: boolean) => void;
}) {
  async function upsertProxyProfile(input: UpsertProxyProfileInput): Promise<void> {
    await commitSnapshotAction(() => api.upsertProxyProfile(input), "Xray profile saved.");
  }

  async function importProxyProfiles(input: ImportProxyProfilesInput): Promise<void> {
    setBusy(true);
    setNotice("");
    try {
      const { snapshot: next, result } = await api.importProxyProfiles(input);
      setSnapshot(next);
      const summary = `Imported ${result.imported}, updated ${result.updated}, skipped ${result.skipped}, failed ${result.failed}.`;
      setNotice(result.errors.length > 0 ? `${summary} ${result.errors[0]}` : summary);
      if (result.imported + result.updated === 0 && result.failed > 0) {
        throw new Error(result.errors[0] ?? "No valid Xray links were imported.");
      }
    } catch (error) {
      const message = toErrorMessage(error);
      setNotice(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }

  async function refreshProxyProfiles(): Promise<void> {
    setBusy(true);
    setNotice("");
    try {
      const { snapshot: next, result } = await api.refreshProxyProfiles();
      setSnapshot(next);
      setNotice(`Refresh complete. Imported ${result.imported}, updated ${result.updated}, stale profiles kept for pinned review.`);
    } catch (error) {
      const message = toErrorMessage(error);
      setNotice(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }

  function acceptXrayRisk(): void {
    updateSettings({
      xrayConsentAccepted: true,
      xrayRiskBannerExpanded: false,
      showXrayWarningOnEnter: false
    });
  }

  return {
    upsertProxyProfile,
    importProxyProfiles,
    refreshProxyProfiles,
    acceptXrayRisk
  };
}
