import { Check, CircleAlert, ClipboardPaste, Copy, KeyRound, Pencil, RotateCcw, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { useLeaveGuard } from "../../../hooks/useNavigation.js";
import { describeError, type DescribedError } from "../../../lib/errors.js";
import {
  Badge,
  Button,
  buttonClass,
  Callout,
  Field,
  Icon,
  LinkButton,
  Modal,
  PasteButton,
  RevealButton,
  SecretInput,
  SecretTextArea,
  Spinner,
  StateLine,
  TextInput
} from "../../ui/index.js";
import { analyzeKeyText, keyTextProblem, keyTextWarning, revealAfterKeyEdit, type KeyReveal } from "./key-text.js";
import { findAddedId, joinNames, keySavedToast, keySupportIssue, keyTypeLabel, serversUsingKey, shortKeyId } from "./key-model.js";

export interface KeyFormRequest {
  /** New object per open; the form state resets for each one. */
  token: number;
  mode: "create" | "edit";
  keyId?: string;
  /** Opened from the server form ("Add a new key"): the saved key is picked there. */
  forServer?: { name: string };
  /** Opened for a server that isn't started yet: a new server form opens with the key picked. */
  opensNewServer?: boolean;
}

let lastFormToken = 0;

/** A fresh token for a form request (each one starts the form from scratch). */
export function nextFormToken(): number {
  lastFormToken += 1;
  return lastFormToken;
}

export interface KeyFormModalProps {
  request: KeyFormRequest | null;
  onClose: () => void;
  /** Called with the saved key's id before the form closes. */
  onSaved?: (keyId: string) => void;
}

/**
 * Add / edit key dialog. Keeps the last request mounted while the dialog
 * plays its exit animation; every open starts from a fresh form (secrets
 * hidden, nothing pasted).
 */
export function KeyFormModal({ request, onClose, onSaved }: KeyFormModalProps): JSX.Element | null {
  const [current, setCurrent] = useState<KeyFormRequest | null>(request);
  if (request && request !== current) {
    setCurrent(request);
  }
  if (!current) {
    return null;
  }
  return <KeyForm key={current.token} request={current} open={request !== null && request === current} onClose={onClose} onSaved={onSaved} />;
}

type CopyState = "idle" | "busy" | "done" | "error";

const COPIED_MS = 2200;

function isDecryptFailure(message: string): boolean {
  return /decrypt|secret record is missing|secure storage|fallback secret/iu.test(message);
}

function KeyForm({ request, open, onClose, onSaved }: { request: KeyFormRequest; open: boolean; onClose: () => void; onSaved?: (keyId: string) => void }): JSX.Element {
  const { store, run, toast, confirm } = useAppData();
  const key = request.keyId ? store.sshKeys.find((candidate) => candidate.id === request.keyId) : undefined;
  const editing = request.mode === "edit";
  const ids = useId();
  const nameId = `${ids}-name`;
  const keyFieldId = `${ids}-key`;
  const keyErrorId = `${ids}-key-error`;
  const keyStateId = `${ids}-key-state`;
  const passStateId = `${ids}-pass-state`;

  const [initialName] = useState(key?.name ?? "");
  const [name, setName] = useState(initialName);
  const [keyText, setKeyText] = useState("");
  const [reveal, setReveal] = useState<KeyReveal>({ shown: false, auto: false });
  const shown = reveal.shown;
  const [passphrase, setPassphrase] = useState("");
  const [nameError, setNameError] = useState<string>();
  const [keyRequired, setKeyRequired] = useState<string>();
  const [errorBump, setErrorBump] = useState(0);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<DescribedError>();
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const [copyError, setCopyError] = useState<DescribedError>();
  const copyTimer = useRef<number>();
  const keyAreaRef = useRef<HTMLTextAreaElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => () => window.clearTimeout(copyTimer.current), []);

  // The key was deleted somewhere else while this form was open.
  const missing = editing && !key;
  useEffect(() => {
    if (open && missing) {
      onClose();
      toast({ tone: "info", title: "That key is no longer saved", message: "It was deleted, so there is nothing to edit." });
    }
  }, [missing, onClose, open, toast]);

  const analysis = useMemo(() => analyzeKeyText(keyText), [keyText]);
  const problem = keyTextProblem(analysis);
  const warning = keyTextWarning(analysis);
  const hasNewKey = analysis.kind !== "empty";
  const savedPassphrase = Boolean(key?.privateKeyPassphraseSecretId);
  const needsPassphrase = analysis.kind === "private" && analysis.needsPassphrase && !passphrase && !savedPassphrase;
  const users = key ? serversUsingKey(store.sshConfigs, key.id) : [];
  const issue = key && !hasNewKey ? keySupportIssue(key) : undefined;
  const dirty = name.trim() !== initialName.trim() || hasNewKey || passphrase.length > 0;
  const keyError = problem?.message ?? keyRequired;

  const save = async (): Promise<void> => {
    if (saving) {
      return;
    }
    const missingName = name.trim() ? undefined : "Enter a name, for example work-ed25519.";
    const missingKey = !editing && !hasNewKey ? "Paste the private key text. It starts with -----BEGIN … PRIVATE KEY-----." : undefined;
    if (missingName || missingKey || problem) {
      setNameError(missingName);
      setKeyRequired(missingKey);
      setErrorBump((count) => count + 1);
      if (missingName) {
        nameRef.current?.focus();
      } else {
        keyAreaRef.current?.focus();
      }
      return;
    }
    setSaving(true);
    setFormError(undefined);
    const before = store.sshKeys;
    try {
      const next = await run(
        () =>
          api.upsertKey({
            id: editing ? key?.id : undefined,
            name: name.trim(),
            privateKey: hasNewKey ? keyText : undefined,
            privateKeyPassphrase: passphrase || undefined
          }),
        { silent: true, rethrow: true }
      );
      const savedId = editing ? key?.id : next ? findAddedId(before, next.store.sshKeys) : undefined;
      toast({
        tone: "success",
        ...keySavedToast({
          mode: editing ? "edit" : "create",
          name: name.trim(),
          replaced: editing && hasNewKey,
          usedBy: users.map((config) => config.name),
          pickedFor: request.opensNewServer ? "a new server" : request.forServer?.name
        })
      });
      if (savedId) {
        onSaved?.(savedId);
      }
      onClose();
    } catch (error) {
      setFormError(describeError(error, { title: "Couldn't save the key" }));
    } finally {
      setSaving(false);
    }
  };

  /** "Discard changes?"; resolves true once the form was closed. */
  const confirmDiscard = (): Promise<boolean> => {
    const savedName = key?.name ?? "";
    let description: string;
    if (!editing) {
      description = `${name.trim() || "This key"} isn’t saved yet. If you close now, what you ${hasNewKey ? "pasted" : "typed"} is lost.`;
    } else if (hasNewKey) {
      description = `The key you pasted isn’t saved yet. ${savedName} keeps its saved key.`;
    } else {
      description = `Your edits aren’t saved yet. ${savedName} keeps its saved key and passphrase.`;
    }
    return confirm({
      eyebrow: "SSH keys",
      tone: "warn",
      icon: Pencil,
      title: editing ? `Discard changes to ${savedName}?` : "Discard this new key?",
      description,
      confirmLabel: editing ? "Discard changes" : "Discard",
      cancelLabel: "Keep editing"
    }).then((confirmed) => {
      if (confirmed) {
        onClose();
        toast({
          tone: "info",
          title: "Changes discarded",
          message: editing ? `${savedName} keeps its saved key and passphrase.` : "Nothing was added to SSH keys."
        });
      }
      return confirmed;
    });
  };

  const requestClose = (): void => {
    if (saving) {
      return;
    }
    if (!dirty) {
      onClose();
      return;
    }
    void confirmDiscard();
  };

  // A toast's "Open …" link sits above the scrim; following it asks first too.
  useLeaveGuard(open && dirty && !saving ? confirmDiscard : undefined);

  const copySaved = async (): Promise<void> => {
    if (!key || copyState === "busy") {
      return;
    }
    window.clearTimeout(copyTimer.current);
    setCopyState("busy");
    setCopyError(undefined);
    try {
      const copied = await api.copyPrivateKey(key.id);
      if (!copied) {
        throw new Error("The clipboard didn’t accept the key. Try again.");
      }
      setCopyState("done");
      copyTimer.current = window.setTimeout(() => setCopyState("idle"), COPIED_MS);
    } catch (error) {
      const described = describeError(error);
      setCopyError(described);
      setCopyState("error");
    }
  };

  const keyRows = analysis.kind === "empty" ? 5 : analysis.kind === "private" ? 8 : 3;
  const passPlaceholder = savedPassphrase ? "Leave blank to keep the saved passphrase" : "Only if the key has one";
  const decryptFailure = copyError ? isDecryptFailure(copyError.technical ?? copyError.message) : false;
  const copyLive = copyState === "done" ? "Saved key copied to the clipboard." : copyState === "error" ? "Copy failed. The saved key can’t be decrypted." : "";

  return (
    <Modal
      open={open && !missing}
      onClose={requestClose}
      eyebrow="SSH keys"
      title={editing ? "Edit key" : "Add key"}
      description={
        editing
          ? "A replaced key is used from the next connect of every server that signs in with it."
          : request.forServer
            ? "Save it and it’s picked in the server form automatically — your server draft stays as it is."
            : request.opensNewServer
              ? "Save it, and a new server opens with this key already picked."
              : "Paste the private key text. It’s encrypted before it’s saved and stays on this device."
      }
      icon={KeyRound}
      iconTone="busy"
      busy={saving}
      onSubmit={() => void save()}
      footer={
        <>
          {saving ? <span className="modal-foot-note">Closing waits until saving is done.</span> : null}
          <Button disabled={saving} onClick={requestClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" busy={saving} busyLabel="Saving…">
            Save key
          </Button>
        </>
      }
    >
      <fieldset className="fm-fieldset" disabled={saving}>
        <legend className="sr-only">Key details</legend>

        {formError ? (
          <Callout tone="danger" title={formError.title} role="alert">
            {formError.message}
          </Callout>
        ) : null}

        {editing && key ? (
          <div className="fm-keymeta">
            <Badge tone="outline" square title="Key type">
              {keyTypeLabel(key.keyType)}
            </Badge>
            <span className="fm-keyid">
              Key ID <span className="mono">{shortKeyId(key.fingerprint)}</span>
            </span>
            <Badge tone="outline" icon={Server}>
              {users.length > 0 ? `Used by ${joinNames(users.map((config) => config.name))}` : "Not used by any server"}
            </Badge>
            {issue ? (
              <Badge tone="warn" icon={TriangleAlert} title={issue}>
                Can’t sign in yet
              </Badge>
            ) : null}
          </div>
        ) : null}

        <Field label="Name" id={nameId} error={nameError} hint="Shown in the key picker of the server form, next to the type and Key ID.">
          <TextInput
            ref={nameRef}
            value={name}
            autoComplete="off"
            placeholder="For example work-ed25519"
            onChange={(event) => {
              setName(event.target.value);
              setNameError(undefined);
            }}
          />
        </Field>

        <div className="field">
          <div className="label-row">
            <label className="label" htmlFor={keyFieldId}>
              Private key
            </label>
            <div className="label-tools">
              <PasteButton
                label="Paste private key from clipboard"
                onPaste={(text) => {
                  setKeyText(text);
                  // A public key isn't secret: show it, so it's clear what was pasted.
                  const isPublic = analyzeKeyText(text).kind === "public";
                  setReveal({ shown: isPublic, auto: isPublic });
                  setKeyRequired(undefined);
                }}
              />
              <RevealButton shown={shown} onShownChange={(next) => setReveal({ shown: next, auto: false })} secretName="private key" />
            </div>
          </div>

          {editing && analysis.kind === "empty" ? (
            <StateLine tone="ok" icon={ShieldCheck} id={keyStateId}>
              <b>A key is saved</b> · paste a new one to replace it
            </StateLine>
          ) : null}
          {editing && hasNewKey && !problem ? (
            <StateLine
              tone="accent"
              icon={ClipboardPaste}
              id={keyStateId}
              action={
                <LinkButton
                  icon={null}
                  onClick={() => {
                    setKeyText("");
                    setReveal({ shown: false, auto: false });
                  }}
                >
                  Undo
                </LinkButton>
              }
            >
              <b>New key pasted</b> · it replaces the saved one when you save
            </StateLine>
          ) : null}

          <SecretTextArea
            ref={keyAreaRef}
            id={keyFieldId}
            className="fm-keyarea"
            shown={shown}
            value={keyText}
            onValueChange={(value) => {
              setKeyText(value);
              setKeyRequired(undefined);
              setReveal((current) => revealAfterKeyEdit(current, value));
            }}
            rows={keyRows}
            invalid={Boolean(keyError)}
            placeholder={editing ? "Leave empty to keep the saved key" : "-----BEGIN OPENSSH PRIVATE KEY-----"}
            aria-describedby={[keyError ? keyErrorId : undefined, editing ? keyStateId : undefined].filter(Boolean).join(" ") || undefined}
          />

          {keyError ? (
            <div className="stack-sm anim-swap" key={`key-error-${errorBump}-${problem?.message ?? ""}`} id={keyErrorId} role="alert">
              <div className="error-text">
                <Icon icon={CircleAlert} size="sm" />
                <span>{keyError}</span>
              </div>
              {problem?.hint ? (
                <span className="hint">
                  {problem.hint} <span className="fm-cmd">{problem.file}</span>
                </span>
              ) : null}
            </div>
          ) : null}
          {warning ? (
            <StateLine tone="warn" icon={TriangleAlert}>
              {warning}
            </StateLine>
          ) : null}
          {needsPassphrase ? (
            <StateLine tone="warn" icon={TriangleAlert}>
              <b>This key is protected with a passphrase.</b> Type it below, or signing in will fail.
            </StateLine>
          ) : null}
          <span className="hint">RSA and Ed25519 keys sign in. ECDSA and DSA keys can be saved but can't sign in yet.</span>
        </div>

        <Field
          label="Passphrase"
          optional
          labelAside={
            savedPassphrase ? (
              <Badge tone="ok" icon={Check}>
                Saved
              </Badge>
            ) : undefined
          }
          hint="Works with PEM and PKCS#8 keys. Passphrase-protected OpenSSH keys aren't supported yet."
          after={
            savedPassphrase ? (
              <StateLine tone="ok" icon={ShieldCheck} id={passStateId}>
                <b>Passphrase saved</b> — leave blank to keep it.
              </StateLine>
            ) : undefined
          }
        >
          <SecretInput
            value={passphrase}
            onValueChange={setPassphrase}
            secretName="passphrase"
            placeholder={passPlaceholder}
            aria-describedby={savedPassphrase ? passStateId : undefined}
          />
        </Field>

        {editing && key ? (
          <div className="fm-copyblock">
            <div className="fm-copyrow">
              <div className="fm-copytext">
                <span className="fm-copytitle">Copy saved key</span>
                <span className="hint">Decrypts the saved private key and puts it on your clipboard, for moving it to another device.</span>
              </div>
              <button
                type="button"
                className={buttonClass("secondary", "sm", "fm-copybtn")}
                data-done={copyState === "done" ? "true" : undefined}
                disabled={copyState === "busy"}
                aria-busy={copyState === "busy" || undefined}
                onClick={() => void copySaved()}
              >
                <span className="fm-inner anim-swap" key={copyState}>
                  {copyState === "busy" ? (
                    <>
                      <Spinner />
                      Decrypting…
                    </>
                  ) : copyState === "done" ? (
                    <>
                      <Icon icon={Check} size="sm" />
                      Copied
                    </>
                  ) : copyState === "error" ? (
                    <>
                      <Icon icon={RotateCcw} size="sm" />
                      Try again
                    </>
                  ) : (
                    <>
                      <Icon icon={Copy} size="sm" />
                      Copy saved key
                    </>
                  )}
                </span>
              </button>
            </div>
            {copyState === "error" && copyError ? (
              <Callout tone="danger" icon={TriangleAlert} role="alert" className="anim-swap" title={decryptFailure ? "Can't decrypt the saved key" : "Couldn’t copy the saved key"}>
                {decryptFailure
                  ? "Saved secrets can't be read after the app folder moves to another PC or the system keychain is reset. Paste the key again to replace it."
                  : copyError.message}
                {decryptFailure || copyError.technical ? <span className="fm-tech">{copyError.technical ?? copyError.message}</span> : null}
              </Callout>
            ) : null}
            <StateLine tone="warn" icon={TriangleAlert}>
              <b>Your clipboard isn't cleared automatically.</b> Paste the key where you need it, then copy something else over it.
            </StateLine>
            <span className="sr-only" aria-live="polite">
              {copyLive}
            </span>
          </div>
        ) : null}
      </fieldset>
    </Modal>
  );
}
