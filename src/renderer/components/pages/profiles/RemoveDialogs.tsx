import { TriangleAlert } from "lucide-react";
import type { ProxyProfile } from "../../../../shared/types.js";
import { protocolLabel } from "../../../lib/format.js";
import { Badge, Callout, ConfirmDialog } from "../../ui/index.js";
import type { BulkRemoveCopy } from "./profile-presenter.js";
import { singleRemoveCopy } from "./profile-presenter.js";

interface RemoveDialogBase {
  open: boolean;
  busy: boolean;
  error?: unknown;
  onConfirm: () => void;
  onCancel: () => void;
}

/** "Remove “nl-ams-ws”?" with the profile, its address and source, and how to get it back. */
export function RemoveProfileDialog({ profile, ...dialog }: RemoveDialogBase & { profile?: ProxyProfile }): JSX.Element | null {
  if (!profile) {
    return null;
  }
  const copy = singleRemoveCopy(profile);
  return (
    <ConfirmDialog
      {...dialog}
      eyebrow="Xray profiles"
      title={copy.title}
      description={copy.description}
      confirmLabel="Remove profile"
      busyLabel="Removing…"
      errorTitle="Couldn’t remove the profile"
      body={
        <>
          <div className="pf-cf-item">
            <Badge square tone="outline">
              {protocolLabel(profile.protocol)}
            </Badge>
            <div className="pf-cf-copy">
              <span className="pf-cf-name truncate">{profile.name}</span>
              <span className="mono faint truncate">{copy.meta}</span>
            </div>
          </div>
          <p className="hint pf-cf-foot">{copy.footnote}</p>
        </>
      }
    />
  );
}

/** "Remove 116 unpinned profiles?" with the counts and what happens to a running Xray tunnel. */
export function RemoveUnpinnedDialog({ copy, busyLabel, ...dialog }: RemoveDialogBase & { copy?: BulkRemoveCopy; busyLabel: string }): JSX.Element | null {
  if (!copy) {
    return null;
  }
  return (
    <ConfirmDialog
      {...dialog}
      eyebrow="Xray profiles"
      title={copy.title}
      description={copy.description}
      confirmLabel={copy.confirmLabel}
      busyLabel={busyLabel}
      errorTitle="Couldn’t remove the profiles"
      body={
        <>
          <div className="facts">
            <div className="fact">
              <span className="fact-label">Removed</span>
              <span className="pf-big is-danger">{copy.removed}</span>
              <span className="hint">{copy.removedHint}</span>
            </div>
            <div className="fact">
              <span className="fact-label">Kept</span>
              <span className="pf-big">{copy.kept}</span>
              <span className="hint">{copy.kept === "1" ? "pinned profile" : "pinned profiles"}</span>
            </div>
          </div>
          {copy.xrayWarning ? (
            <Callout tone="warn" icon={TriangleAlert} title="Xray disconnects first">
              {copy.xrayWarning}
            </Callout>
          ) : (
            <Callout tone="info" title="Nothing disconnects">
              {copy.calmNote}
            </Callout>
          )}
          <p className="hint pf-cf-foot">{copy.footnote}</p>
        </>
      }
    />
  );
}
