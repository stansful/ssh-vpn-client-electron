import { Check, Info, List, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { describeError, type DescribedError } from "../../../lib/errors.js";
import { formatCount, plural } from "../../../lib/format.js";
import { Button, Callout, cx, Field, Icon, IconTile, LinkButton, Modal, ToggleRow } from "../../ui/index.js";
import {
  boxHoldsLine,
  buildImportReport,
  contentLineCount,
  describeImportNotes,
  describeInsecureLines,
  describeProfileLimit,
  editImportBox,
  EMPTY_IMPORT_BOX,
  fixBoxLine,
  gutterNumber,
  importedSentence,
  isProfileLimitError,
  linesHint,
  matchLinksToLibrary,
  trimTrailingBlankLines,
  visualLineCount,
  type ImportBox,
  type ImportFailureItem,
  type ImportReport
} from "./import-lines.js";
import { applySchemeFix } from "./link-preview.js";
import { DIALOG_EXIT_MS } from "./profile-presenter.js";

const ROW_HEIGHT = 22;
const MAX_VISIBLE_ROWS = 12;

export interface ImportLinksDialogProps {
  open: boolean;
  onClose: () => void;
  /** Links handed over from Add profile; a new `seq` adds them to the box. */
  prefill?: { text: string; seq: number };
  /** Opens the Remove unpinned confirmation (from the over-the-limit callout). */
  onRemoveUnpinned: () => void;
  canRemoveUnpinned: boolean;
}

type Phase = "paste" | "result" | "limit";

/**
 * Import links (Dialogs.dc.html): a line-numbered box, result tiles, every
 * failed line listed and fixable, and the option to keep failed lines in the
 * box. It stays open after a partial import; the draft survives closing.
 */
export function ImportLinksDialog({ open, onClose, prefill, onRemoveUnpinned, canRemoveUnpinned }: ImportLinksDialogProps): JSX.Element {
  const { store, run } = useAppData();
  const [box, setBox] = useState<ImportBox>(EMPTY_IMPORT_BOX);
  const [phase, setPhase] = useState<Phase>("paste");
  const [report, setReport] = useState<ImportReport>();
  const [reportKey, setReportKey] = useState(0);
  const [notes, setNotes] = useState<string>();
  const [doneSentence, setDoneSentence] = useState("");
  const [keep, setKeep] = useState(true);
  const [kept, setKept] = useState<ImportBox>(EMPTY_IMPORT_BOX);
  const [fixed, setFixed] = useState<ReadonlyMap<number, string>>(new Map());
  const [limitText, setLimitText] = useState("");
  const [error, setError] = useState<DescribedError>();
  const [busy, setBusy] = useState(false);
  const storeRef = useRef(store);
  storeRef.current = store;
  const gutterRef = useRef<HTMLDivElement>(null);
  const pastedRef = useRef(false);

  const resetAfterClose = useRef<() => void>();
  const resetTimer = useRef<number>();
  useEffect(() => () => window.clearTimeout(resetTimer.current), []);
  // Declared before the prefill effect: a pending reset must not wipe links handed over on open.
  useEffect(() => {
    if (open && resetAfterClose.current) {
      // Reopened before the reset ran: apply it now.
      window.clearTimeout(resetTimer.current);
      resetAfterClose.current();
    }
  }, [open]);

  useEffect(() => {
    if (!prefill) {
      return;
    }
    setBox((current) => ({
      text: current.text.trim() ? `${trimTrailingBlankLines(current.text)}\n${prefill.text}` : prefill.text,
      lineNumbers: null
    }));
    setPhase("paste");
    setReport(undefined);
    setError(undefined);
    // Only a new hand-over (seq) should add text.
  }, [prefill?.seq]);

  const finished = phase === "result" && (report?.outcome === "clean" || report?.outcome === "nothing");
  const hint = linesHint(box);
  const failedLines = useMemo(() => new Set(phase === "result" && report ? report.failures.map((item) => item.line) : []), [phase, report]);

  const close = (): void => {
    if (busy) {
      return;
    }
    onClose();
    const clearBox = finished;
    // What you saw stays seen; the box text (and its numbering) is the draft.
    // Reset once the dialog has finished closing, so it doesn't change under you.
    resetAfterClose.current = () => {
      resetAfterClose.current = undefined;
      if (clearBox) {
        setBox(EMPTY_IMPORT_BOX);
        setKept(EMPTY_IMPORT_BOX);
      }
      setPhase("paste");
      setReport(undefined);
      setNotes(undefined);
      setLimitText("");
      setError(undefined);
      setFixed(new Map());
    };
    window.clearTimeout(resetTimer.current);
    resetTimer.current = window.setTimeout(() => resetAfterClose.current?.(), DIALOG_EXIT_MS);
  };

  const runImport = async (): Promise<void> => {
    if (busy) {
      return;
    }
    const sent: ImportBox = { text: trimTrailingBlankLines(box.text), lineNumbers: box.lineNumbers };
    if (contentLineCount(sent.text) === 0 || linesHint(sent).blocked) {
      return;
    }
    const before = storeRef.current.proxyProfiles;
    setBusy(true);
    setError(undefined);
    try {
      const response = await run(() => api.importProxyProfiles({ text: sent.text, source: "clipboard" }), { silent: true, rethrow: true });
      if (!response) {
        return;
      }
      const next = buildImportReport(sent, response.result);
      const match = next.updated > 0 ? await matchLinksToLibrary(sent, before) : undefined;
      setNotes(describeImportNotes(sent, next, match));
      setReport(next);
      setReportKey((key) => key + 1);
      setFixed(new Map());
      setKept(next.kept);
      setLimitText("");
      if (next.outcome === "clean" || next.outcome === "nothing") {
        setBox(EMPTY_IMPORT_BOX);
        // The notes line only shows with a partial result, so the insecure=1 note joins the success text.
        setDoneSentence([importedSentence(before, response.snapshot.store.proxyProfiles), describeInsecureLines(sent)].filter(Boolean).join(" "));
      } else {
        setBox(keep ? next.kept : EMPTY_IMPORT_BOX);
      }
      setPhase("result");
    } catch (failure) {
      if (isProfileLimitError(failure)) {
        setReport(undefined);
        setLimitText(describeProfileLimit(before.length, await matchLinksToLibrary(sent, before)));
        setPhase("limit");
      } else {
        setError(describeError(failure, { title: "Couldn’t import these links" }));
      }
    } finally {
      setBusy(false);
    }
  };

  const applyFix = (item: ImportFailureItem): void => {
    if (!item.fix) {
      return;
    }
    const to = item.fix.to;
    setKept((current) => fixBoxLine(current, item.line, to));
    setBox((current) => (keep && boxHoldsLine(current, item.line) ? fixBoxLine(current, item.line, to) : fixBoxLine(kept, item.line, to)));
    setKeep(true);
    setFixed((current) => new Map(current).set(item.line, to));
  };

  const toggleKeep = (next: boolean): void => {
    setKeep(next);
    setBox(next ? kept : EMPTY_IMPORT_BOX);
  };

  let primaryLabel = "Import";
  if (phase === "result" && !finished) {
    primaryLabel = "Import again";
  } else if (finished) {
    primaryLabel = "Close";
  }
  const primaryDisabled = !finished && (hint.blocked === true || busy);

  const rows = Math.max(1, visualLineCount(box.text));
  const areaStyle: CSSProperties = { height: Math.min(rows, MAX_VISIBLE_ROWS) * ROW_HEIGHT + 32 };

  return (
    <Modal
      open={open}
      onClose={close}
      busy={busy}
      icon={List}
      iconTone="busy"
      eyebrow="Xray profiles"
      title="Import links"
      description="Paste one share link per line. Empty lines and lines starting with # are skipped. Links you already have are updated, not duplicated."
      footer={
        <>
          {busy ? <span className="modal-foot-note">Closing waits until the import is done.</span> : null}
          {!finished ? (
            <Button disabled={busy} onClick={close}>
              {phase === "result" ? "Close" : "Cancel"}
            </Button>
          ) : null}
          <Button
            variant="primary"
            busy={busy}
            busyLabel="Importing…"
            disabled={primaryDisabled}
            onClick={() => {
              if (finished) {
                close();
              } else {
                void runImport();
              }
            }}
          >
            {primaryLabel}
          </Button>
        </>
      }
    >
      {phase === "limit" ? (
        <Callout tone="danger" icon={TriangleAlert} title="Nothing was imported" role="alert" className="anim-swap">
          {limitText}
          {canRemoveUnpinned ? (
            <span className="pf-callout-action">
              <LinkButton icon={null} onClick={onRemoveUnpinned}>
                Remove unpinned…
              </LinkButton>
            </span>
          ) : null}
        </Callout>
      ) : null}

      {error ? (
        <Callout tone="danger" title={error.title} role="alert" className="anim-swap">
          {error.message}
        </Callout>
      ) : null}

      {phase === "result" && report && !finished ? (
        <ImportResult
          key={reportKey}
          report={report}
          notes={notes}
          fixed={fixed}
          canFix={(item) => !keep || boxHoldsLine(box, item.line)}
          onFix={applyFix}
          keep={keep}
        />
      ) : null}

      {phase === "result" && report && finished ? (
        report.outcome === "clean" ? (
          <Callout tone="ok" icon={ShieldCheck} title="All lines imported" role="status" className="anim-swap">
            {`${report.countsLine}.${doneSentence ? ` ${doneSentence}` : ""}`}
          </Callout>
        ) : (
          <Callout tone="info" icon={Info} title="Nothing to import" role="status" className="anim-swap">
            Every line was empty or a comment, so nothing changed.
          </Callout>
        )
      ) : null}

      {phase === "result" && report && !finished ? (
        <ToggleRow
          className="pf-toggle"
          title="Keep failed lines in the box"
          description="Imported lines are cleared. Failed ones stay with their line numbers so you can fix them."
          checked={keep}
          disabled={busy}
          onCheckedChange={toggleKeep}
        />
      ) : null}

      <Field label="Links" labelAside={<span className={cx("hint", hint.tone === "danger" && "pf-hint-danger")}>{hint.text}</span>}>
        {(control) => (
          <div className="pf-code">
            <div className="pf-gutter" aria-hidden="true" ref={gutterRef}>
              <Gutter box={box} rows={rows} failed={failedLines} fixed={fixed} />
            </div>
            <textarea
              id={control.id}
              aria-describedby={control.describedBy}
              className="pf-code-area"
              wrap="off"
              spellCheck={false}
              autoComplete="off"
              autoCapitalize="off"
              placeholder="Paste one share link per line"
              disabled={busy}
              value={box.text}
              style={areaStyle}
              onPaste={() => {
                pastedRef.current = true;
              }}
              onChange={(event) => {
                const text = event.target.value;
                const wasPaste = pastedRef.current;
                pastedRef.current = false;
                setBox((current) => (wasPaste ? { text, lineNumbers: null } : editImportBox(current, text)));
              }}
              onScroll={(event) => {
                if (gutterRef.current) {
                  gutterRef.current.scrollTop = event.currentTarget.scrollTop;
                }
              }}
            />
          </div>
        )}
      </Field>
    </Modal>
  );
}

function Gutter({ box, rows, failed, fixed }: { box: ImportBox; rows: number; failed: ReadonlySet<number>; fixed: ReadonlyMap<number, string> }): JSX.Element {
  if (!box.lineNumbers) {
    // Plain numbering: one text node, cheap even for 10,000 lines.
    return <span className="pf-gutter-seq">{Array.from({ length: rows }, (_, index) => index + 1).join("\n")}</span>;
  }
  return (
    <>
      {Array.from({ length: rows }, (_, index) => {
        const number = gutterNumber(box, index);
        const tone = fixed.has(number) ? "ok" : failed.has(number) ? "err" : undefined;
        return (
          <span key={`${index}-${number}`} data-tone={tone}>
            {formatCount(number)}
          </span>
        );
      })}
    </>
  );
}

function ImportResult({
  report,
  notes,
  fixed,
  canFix,
  onFix,
  keep
}: {
  report: ImportReport;
  notes?: string;
  fixed: ReadonlyMap<number, string>;
  canFix: (item: ImportFailureItem) => boolean;
  onFix: (item: ImportFailureItem) => void;
  keep: boolean;
}): JSX.Element {
  const stats: Array<{ label: string; value: number; tone?: string }> = [
    { label: "Imported", value: report.imported, tone: "ok" },
    { label: "Updated", value: report.updated, tone: "info" },
    { label: "Skipped", value: report.skipped },
    { label: "Failed", value: report.failed, tone: "danger" }
  ];
  return (
    <div className="pf-result anim-swap" role="status">
      <div className="pf-result-head">
        <IconTile icon={TriangleAlert} tone={report.outcome === "failed" ? "danger" : "warn"} size="sm" />
        <span className="pf-result-title">{report.title}</span>
        <span className="sr-only">{report.countsLine}</span>
      </div>
      <div className="pf-stats" aria-hidden="true">
        {stats.map((stat, index) => (
          <div key={stat.label} className="pf-stat rise" data-tone={stat.tone} style={{ "--d": index + 1 } as CSSProperties}>
            <span className="pf-stat-num">{formatCount(stat.value)}</span>
            <span className="pf-stat-label">{stat.label}</span>
          </div>
        ))}
      </div>
      {report.general.length > 0 || report.failures.length > 0 ? (
        <div className="pf-fails">
          {report.general.map((message) => (
            <div key={message} className="pf-fail rise" style={{ "--d": 5 } as CSSProperties}>
              <span className="pf-fail-msg">{message}</span>
            </div>
          ))}
          {report.failures.map((item) => {
            const to = fixed.get(item.line);
            return (
              <div key={item.line} className="pf-fail rise" data-fixed={to ? "true" : "false"} style={{ "--d": 5 } as CSSProperties}>
                <span className="pf-fail-msg">
                  <b>Line {formatCount(item.line)}:</b> {to ? `fixed to ${to}:// and ready to import.` : item.message}
                </span>
                <span className="pf-fail-line" title={item.text.trim()}>
                  {to ? applySchemeFix(item.text, to).trim() : item.text.trim()}
                </span>
                {to ? (
                  <span className="pf-ok-line">
                    <Icon icon={Check} />
                    Fixed in the box below. Import again to add it.
                  </span>
                ) : item.fix && canFix(item) ? (
                  <div className="pf-row-between">
                    <span className="hint">{item.hint}</span>
                    <Button size="sm" onClick={() => onFix(item)}>
                      Change to {item.fix.to}://
                    </Button>
                  </div>
                ) : item.hint ? (
                  <span className="hint">{item.hint}</span>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
      {report.unlisted > 0 ? (
        <span className="hint">
          {plural(report.unlisted, "more failed line")} {report.unlisted === 1 ? "isn’t" : "aren’t"} listed here
          {keep ? `, but ${report.unlisted === 1 ? "it stays" : "they stay"} in the box below` : ""}.
        </span>
      ) : null}
      {notes ? <span className="hint">{notes}</span> : null}
    </div>
  );
}
