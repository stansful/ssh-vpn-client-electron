import { ArrowRight, Check, Download, FileText, Info, Route, ShieldAlert, ShieldCheck, TriangleAlert, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { formatBytes, formatCount, plural } from "../../../lib/format.js";
import { Badge, Button, Callout, cx, Icon, IconTile, Mono, Modal } from "../../ui/index.js";
import { DomainListViewer } from "./DomainListViewer.js";
import { countRuleTypes, describeSkipped, ruleCountsText, type RichText, type RuleImportPreview } from "./rule-import.js";
import { countTargets, listName, wouldCutLastTarget } from "./routing-model.js";
import type { PendingCut, RoutingController, RoutingDialog } from "./useRoutingController.js";

/** Keeps the last value while a dialog plays its exit animation. */
function useLastDefined<T>(value: T | undefined): T | undefined {
  const last = useRef(value);
  if (value !== undefined) {
    last.current = value;
  }
  return value ?? last.current;
}

function dialogOf<K extends RoutingDialog["kind"]>(dialog: RoutingDialog | undefined, kind: K): Extract<RoutingDialog, { kind: K }> | undefined {
  return dialog?.kind === kind ? (dialog as Extract<RoutingDialog, { kind: K }>) : undefined;
}

/** Every dialog the Routing page opens. */
export function RoutingDialogs({ ctl }: { ctl: RoutingController }): JSX.Element {
  const viewer = useLastDefined(dialogOf(ctl.dialog, "viewer"));
  const lastTarget = useLastDefined(dialogOf(ctl.dialog, "last-target"));
  const importing = useLastDefined(dialogOf(ctl.dialog, "import"));
  return (
    <>
      <ModeGuardDialog ctl={ctl} open={ctl.dialog?.kind === "mode-guard"} />
      {lastTarget ? <LastTargetDialog ctl={ctl} open={ctl.dialog?.kind === "last-target"} pending={lastTarget.pending} /> : null}
      {importing ? <ImportRulesDialog ctl={ctl} open={ctl.dialog?.kind === "import"} preview={importing.preview} /> : null}
      {viewer ? <DomainListViewer ctl={ctl} kind={viewer.list} open={ctl.dialog?.kind === "viewer"} /> : null}
    </>
  );
}

/** Asked before switching to Split tunnel with nothing to route. */
function ModeGuardDialog({ ctl, open }: { ctl: RoutingController; open: boolean }): JSX.Element {
  const stayRef = useRef<HTMLButtonElement>(null);
  const name = ctl.sessionName ?? "the tunnel";
  const anyRules = ctl.rules.length > 0;
  const opening = anyRules ? "None of your rules are on and Blocked in Russia is off." : "You haven’t added any rules or turned on Blocked in Russia.";
  const description = ctl.live
    ? `${opening} If you switch now, nothing goes through the tunnel, so ${name} disconnects.`
    : `${opening} If you switch now, Connect stays paused until you add a target.`;
  const listCount = ctl.proxyList.domains.length;
  const fixText = listCount > 0
    ? `${formatCount(listCount)} sites blocked or throttled in Russia go through the tunnel, so Split tunnel has something to route.`
    : "About 2,000 sites blocked or throttled in Russia go through the tunnel. The list downloads from GitHub first, which takes up to 15 s.";

  return (
    <Modal
      open={open}
      onClose={ctl.closeDialog}
      role="alertdialog"
      closeButton={false}
      icon={TriangleAlert}
      iconTone="warn"
      title="Split tunnel has nothing to send yet"
      description={description}
      initialFocusRef={stayRef}
      footer={
        <>
          <Button ref={stayRef} variant="ghost" className="lead" onClick={ctl.closeDialog}>
            Stay on Full tunnel
          </Button>
          <Button variant="danger" onClick={ctl.guardSwitchAnyway}>
            {ctl.live ? "Switch and disconnect" : "Switch anyway"}
          </Button>
          <Button variant="primary" onClick={ctl.guardEnableList}>
            Turn on list and switch
          </Button>
        </>
      }
    >
      <div className="rt-fix">
        <IconTile icon={ShieldCheck} tone="busy" />
        <span className="rt-fix-copy">
          <span className="rt-fix-title">Quickest fix: turn on Blocked in Russia</span>
          <span className="hint">{fixText}</span>
        </span>
      </div>
      <span className="hint">Or stay on Full tunnel and add rules first. Russian services doesn’t count here: it only keeps sites direct.</span>
    </Modal>
  );
}

/** Asked before a change removes the last target of a running Split tunnel. */
function LastTargetDialog({ ctl, open, pending }: { ctl: RoutingController; open: boolean; pending: PendingCut }): JSX.Element {
  const keepRef = useRef<HTMLButtonElement>(null);
  const name = ctl.sessionName ?? "the tunnel";
  const deleting = pending.kind === "delete";
  const undoing = pending.kind === "undo-import";
  const found = pending.kind === "list"
    ? `${listName(pending.list)} list`
    : pending.kind === "undo-import"
      ? plural(pending.count, "imported rule")
      : ctl.rules.find((rule) => rule.id === pending.id)?.value;
  // The rule may be gone while the dialog fades out after "Delete and disconnect".
  const lastValue = useRef(found);
  if (found) {
    lastValue.current = found;
  }
  const value = found ?? lastValue.current ?? "";

  return (
    <Modal
      open={open}
      onClose={ctl.closeDialog}
      role="alertdialog"
      closeButton={false}
      icon={ShieldAlert}
      iconTone="warn"
      title={undoing ? "Undo the import?" : deleting ? "Delete your last target?" : "Turn off your last target?"}
      description={`Split tunnel would have nothing left to send. Rather than quietly sending everything direct, Shadow disconnects ${name}.`}
      initialFocusRef={keepRef}
      footer={
        <>
          <Button ref={keepRef} variant="ghost" className="lead" onClick={ctl.closeDialog}>
            Keep it
          </Button>
          <Button onClick={ctl.lastTargetToFull}>Switch to Full tunnel</Button>
          <Button variant="danger-solid" onClick={ctl.lastTargetConfirm}>
            {undoing ? "Undo and disconnect" : deleting ? "Delete and disconnect" : "Turn off and disconnect"}
          </Button>
        </>
      }
    >
      <div className="rt-file">
        <span className="card-icon" aria-hidden="true">
          <Icon icon={Route} />
        </span>
        <span className="rt-file-copy">
          <span className={cx("rt-file-name", (pending.kind === "toggle" || pending.kind === "delete") && "mono")}>{value}</span>
          <span className="hint">{undoing ? "Your earlier rules have no enabled target" : "Your only enabled target"}</span>
        </span>
      </div>
      <span className="hint">Want to stay connected? Switch to Full tunnel and everything keeps going through {name}.</span>
    </Modal>
  );
}

function RichTextView({ parts }: { parts: RichText }): JSX.Element {
  return (
    <>
      {parts.map((part, index) => ("code" in part ? <Mono key={index}>{part.code}</Mono> : <span key={index}>{part.text}</span>))}
    </>
  );
}

/** Import replaces the whole rule set, so it shows both sides and offers an export first. */
function ImportRulesDialog({ ctl, open, preview }: { ctl: RoutingController; open: boolean; preview: RuleImportPreview }): JSX.Element {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [exported, setExported] = useState<string>();
  const [exporting, setExporting] = useState(false);
  const busy = ctl.importBusy;
  const current = ctl.rules.length;
  const incoming = preview.rules.length;
  const skipped = describeSkipped(preview.skipped);
  const cut = wouldCutLastTarget(ctl.mode, ctl.live, ctl.targets, countTargets(preview.rules, ctl.proxyList));
  const name = ctl.sessionName ?? "the tunnel";

  useEffect(() => {
    setExported(undefined);
  }, [preview]);

  const exportFirst = async (): Promise<void> => {
    setExporting(true);
    try {
      const outcome = await ctl.exportRules();
      if (outcome.saved) {
        setExported(outcome.fileName);
      }
    } finally {
      setExporting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={ctl.closeDialog}
      role="alertdialog"
      closeButton={false}
      eyebrow="Routing · import"
      icon={Upload}
      iconTone="warn"
      title={current > 0 ? `Replace all ${plural(current, "rule")}?` : `Import ${plural(incoming, "rule")}?`}
      description={
        current > 0
          ? "Importing replaces your whole rule set (domains, IPs and apps) with the rules in the file. Nothing is merged."
          : "You don’t have any rules yet, so nothing gets replaced."
      }
      busy={busy}
      initialFocusRef={cancelRef}
      footer={
        <>
          <Button
            variant="ghost"
            className="lead"
            icon={exported ? Check : Download}
            done={Boolean(exported)}
            busy={exporting}
            disabled={current === 0 || busy}
            onClick={() => void exportFirst()}
          >
            {exported ? "Exported" : "Export current rules"}
          </Button>
          <Button ref={cancelRef} disabled={busy} onClick={ctl.closeDialog}>
            Cancel
          </Button>
          <Button
            variant={current > 0 ? "danger-solid" : "primary"}
            busy={busy}
            busyLabel={current > 0 ? "Replacing…" : "Importing…"}
            onClick={() => void ctl.confirmImport(preview)}
          >
            {current > 0 ? `Replace ${plural(current, "rule")}` : `Import ${plural(incoming, "rule")}`}
          </Button>
        </>
      }
    >
      <div className="rt-file">
        <span className="card-icon" aria-hidden="true">
          <Icon icon={FileText} />
        </span>
        <span className="rt-file-copy">
          <span className="mono rt-file-name">{preview.fileName}</span>
          <span className="hint">
            {plural(preview.entries, "entry", "entries")} · {formatBytes(preview.size)}
          </span>
        </span>
        <Badge tone="ok">{formatCount(incoming)} valid</Badge>
      </div>

      <div className="rt-compare">
        <div className="rt-compare-cell">
          <span className="eyebrow">Now</span>
          <span className="rt-compare-num">{formatCount(current)}</span>
          <span className="hint">{ruleCountsText(countRuleTypes(ctl.rules))}</span>
        </div>
        <Icon icon={ArrowRight} />
        <div className="rt-compare-cell" data-next="true">
          <span className="eyebrow">After import</span>
          <span className="rt-compare-num">{formatCount(incoming)}</span>
          <span className="hint">{ruleCountsText(preview.counts)}</span>
        </div>
      </div>

      <Callout icon={Info}>
        {skipped ? (
          <>
            <RichTextView parts={skipped} />{" "}
          </>
        ) : null}
        Imported rules keep the on or off state they have in the file.
        {ctl.live && !cut ? " The new rules reach the running tunnel right away." : null}
      </Callout>

      {cut ? (
        <Callout tone="warn" title={`${name} disconnects`}>
          None of the imported rules are on, so Split tunnel would have nothing to route. Shadow disconnects rather than sending everything
          direct.
        </Callout>
      ) : null}

      {exported ? (
        <span className="rt-ok-line">
          <Icon icon={Check} />
          Your {plural(current, "rule was", "rules were")} saved as {exported}
        </span>
      ) : null}
    </Modal>
  );
}
