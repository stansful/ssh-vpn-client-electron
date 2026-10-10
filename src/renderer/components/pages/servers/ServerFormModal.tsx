import { ArrowRight, Check, ChevronDown, KeyRound, Lock, Pencil, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { useLeaveGuard } from "../../../hooks/useNavigation.js";
import { describeError, type DescribedError } from "../../../lib/errors.js";
import { plural } from "../../../lib/format.js";
import {
  Badge,
  Button,
  Callout,
  Collapse,
  Field,
  FieldError,
  Hint,
  Icon,
  Modal,
  NumberStepper,
  SecretInput,
  Segmented,
  StateLine,
  TextArea,
  TextInput
} from "../../ui/index.js";
import { KeyFormModal, nextFormToken, type KeyFormRequest } from "../keys/KeyFormModal.js";
import { FingerprintField, PinBadge } from "./FingerprintField.js";
import { KeyPickerField } from "./KeyPickerField.js";
import {
  advancedSummary,
  analyzeFingerprint,
  connectionPreview,
  DEFAULT_KEEPALIVE_SEC,
  describeServerChanges,
  deviceNoun,
  isServerFormDirty,
  KEEPALIVE_STEP_SEC,
  MAX_KEEPALIVE_SEC,
  MIN_KEEPALIVE_SEC,
  observedKeySuggestion,
  pinState,
  secretsPhrase,
  toUpsertInput,
  validateServerValues,
  valuesFromConfig,
  type FieldChange,
  type ServerField,
  type ServerFieldErrors,
  type ServerFormValues
} from "./server-form-model.js";
import { sshSessionView } from "./server-model.js";
import type { AuthType } from "../../../../shared/types.js";

export interface ServerFormRequest {
  /** New object per open; the form state resets for each one. */
  token: number;
  mode: "create" | "edit";
  configId?: string;
  /** Field to focus first ("Add password", "Choose a key" on a row). */
  focus?: "password" | "key";
  /** Key to pick in a new server (added through the keys page). */
  presetKeyId?: string;
}

export interface ServerFormModalProps {
  request: ServerFormRequest | null;
  onClose: () => void;
}

/** Add / edit server dialog; keeps the last request mounted for the exit animation. */
export function ServerFormModal({ request, onClose }: ServerFormModalProps): JSX.Element | null {
  const [current, setCurrent] = useState<ServerFormRequest | null>(request);
  if (request && request !== current) {
    setCurrent(request);
  }
  if (!current) {
    return null;
  }
  return <ServerForm key={current.token} request={current} open={request !== null && request === current} onClose={onClose} />;
}

const FIELD_ORDER: ServerField[] = ["name", "host", "port", "username", "fingerprint", "keepalive"];

function ChangeList({ changes }: { changes: FieldChange[] }): JSX.Element {
  return (
    <div className="sv-diff">
      {changes.map((change) => (
        <div className="sv-diff-row" key={change.label}>
          <span className="sv-diff-label">{change.label}</span>
          <span className="sv-diff-val">
            <span className="sv-diff-old">{change.from}</span>
            <Icon icon={ArrowRight} />
            <span className="sv-diff-new">{change.to}</span>
          </span>
        </div>
      ))}
    </div>
  );
}

function GroupHead({ id, number, title, aside }: { id: string; number: string; title: string; aside?: ReactNode }): JSX.Element {
  return (
    <div className="fm-group-head">
      <h3 className="fm-group-title" id={id}>
        <span className="fm-num">{number}</span>
        {title}
      </h3>
      {aside}
    </div>
  );
}

function ServerForm({ request, open, onClose }: { request: ServerFormRequest; open: boolean; onClose: () => void }): JSX.Element {
  const { store, snapshot, environment, run, toast, confirm } = useAppData();
  const config = request.configId ? store.sshConfigs.find((candidate) => candidate.id === request.configId) : undefined;
  const editing = request.mode === "edit";
  const ids = useId();
  const fieldId = (field: string): string => `${ids}-${field}`;

  const [initial] = useState<ServerFormValues>(() => valuesFromConfig(config, { privateKeyId: request.presetKeyId }));
  const [values, setValues] = useState<ServerFormValues>(initial);
  const [errors, setErrors] = useState<ServerFieldErrors>({});
  const [fingerprintRevealed, setFingerprintRevealed] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<DescribedError>();
  const [keyForm, setKeyForm] = useState<KeyFormRequest | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  // The key picker's trigger has no ref of its own; find it by the id it gets.
  const keyPickerRef = useMemo<RefObject<HTMLElement>>(() => ({
    get current() {
      return document.getElementById(`${ids}-key`);
    }
  }), [ids]);

  const savedName = config?.name ?? "";
  const displayName = values.name.trim() || savedName || "This server";
  const keyIds = useMemo(() => store.sshKeys.map((key) => key.fingerprint), [store.sshKeys]);
  const fingerprint = analyzeFingerprint(values.fingerprint, keyIds);
  const pin = pinState(values.fingerprint, config?.expectedServerFingerprint ?? "", fingerprint);
  const fingerprintError = (fingerprintRevealed && fingerprint.state === "invalid" ? fingerprint.message : undefined) ?? errors.fingerprint;

  const session = sshSessionView(snapshot);
  const liveState = editing && config && session.on && session.activeId === config.id ? session.state : undefined;
  const observed = liveState && config && !config.expectedServerFingerprint
    ? observedKeySuggestion({
        observed: snapshot.runtime.observedHostKeyFingerprint,
        values,
        saved: config,
        activeTarget: snapshot.runtime.activeTarget
      })
    : undefined;
  const passwordSaved = Boolean(config?.passwordSecretId);
  const usesPassword = values.authType === "password";
  const linkedKey = config?.authType === "private-key" ? store.sshKeys.find((key) => key.id === config.privateKeyId) : undefined;

  // The server was deleted somewhere else while this form was open.
  const missing = editing && !config;
  useEffect(() => {
    if (open && missing) {
      onClose();
      toast({ tone: "info", title: "That server is no longer saved", message: "It was deleted, so there is nothing to edit." });
    }
  }, [missing, onClose, open, toast]);

  const update = <K extends keyof ServerFormValues>(field: K, value: ServerFormValues[K]): void => {
    setValues((current) => ({ ...current, [field]: value }));
    if (field in errors) {
      setErrors((current) => {
        const next = { ...current };
        delete next[field as ServerField];
        return next;
      });
    }
    if (field === "fingerprint") {
      // Errors clear as soon as the value changes; they come back on blur.
      setFingerprintRevealed(false);
    }
  };

  const focusField = (field: ServerField): void => {
    const element = document.getElementById(fieldId(field));
    window.requestAnimationFrame(() => element?.focus());
  };

  const save = async (): Promise<void> => {
    if (saving) {
      return;
    }
    const found = validateServerValues(values, keyIds);
    setFingerprintRevealed(true);
    const firstInvalid = FIELD_ORDER.find((field) => found[field]);
    if (firstInvalid) {
      setErrors(found);
      if (found.keepalive) {
        setAdvancedOpen(true);
      }
      focusField(firstInvalid);
      return;
    }
    setSaving(true);
    setFormError(undefined);
    const hadSelection = Boolean(store.selectedConfigId);
    try {
      const input = toUpsertInput(values, editing ? config?.id : undefined);
      if (input.privateKeyId && !store.sshKeys.some((key) => key.id === input.privateKeyId)) {
        // The picked key was deleted meanwhile; don't save a link to nothing.
        input.privateKeyId = undefined;
      }
      await run(() => api.upsertConfig(input), { silent: true, rethrow: true });
      const name = values.name.trim();
      if (!editing) {
        toast({
          tone: "success",
          title: "Server added",
          message: hadSelection ? `${name} is in SSH servers. Pick it on Connect when you need it.` : `${name} is in SSH servers, and Connect will use it.`
        });
      } else {
        toast({
          tone: "success",
          title: "Changes saved",
          message: liveState ? `${name} uses them from your next connect.` : `${name} is up to date.`
        });
      }
      onClose();
    } catch (error) {
      const described = describeError(error, { title: editing ? "Couldn't save the changes" : "Couldn't add the server" });
      if (/fingerprint/iu.test(described.message)) {
        setErrors((current) => ({ ...current, fingerprint: described.message }));
        focusField("fingerprint");
      } else {
        setFormError(described);
      }
    } finally {
      setSaving(false);
    }
  };

  const dirty = isServerFormDirty(initial, values);

  /** "Discard changes?"; resolves true once the form was closed. */
  const confirmDiscard = (): Promise<boolean> => {
    const changes = editing ? describeServerChanges(initial, values, { keys: store.sshKeys, passwordSaved }) : [];
    return confirm({
      eyebrow: "SSH servers",
      tone: "warn",
      icon: Pencil,
      title: editing ? `Discard changes to ${savedName}?` : "Discard this new server?",
      description: editing
        ? `You changed ${plural(changes.length, "field")}. If you close now, these edits are lost and the server keeps its saved settings.`
        : `${values.name.trim() || "This server"} isn’t saved yet. If you close now, what you typed is lost.`,
      body: changes.length > 0 ? <ChangeList changes={changes} /> : undefined,
      confirmLabel: editing ? "Discard changes" : "Discard",
      cancelLabel: "Keep editing"
    }).then((confirmed) => {
      if (confirmed) {
        onClose();
        toast({
          tone: "info",
          title: "Changes discarded",
          message: editing ? `${savedName} keeps its saved settings.` : "Nothing was added to SSH servers."
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

  const openAddKey = (): void => {
    setKeyForm({ token: nextFormToken(), mode: "create", forServer: { name: values.name.trim() } });
  };

  let passwordState: ReactNode;
  if (editing && passwordSaved) {
    passwordState = (
      <StateLine tone="ok" icon={ShieldCheck} id={fieldId("password-state")}>
        <b>A password is saved</b> — leave blank to keep it, or type a new one to replace it.
      </StateLine>
    );
  } else if (editing && !values.password) {
    passwordState = (
      <StateLine tone="warn" icon={TriangleAlert} id={fieldId("password-state")}>
        <b>No password saved</b> — add one here, or connecting will stop at sign-in.
      </StateLine>
    );
  } else {
    passwordState = <Hint id={fieldId("password-state")}>{`${secretsPhrase(environment.secretsBackend)} Copy takes what you typed here.`}</Hint>;
  }

  const authOptions = [
    { value: "password" as AuthType, label: "Password", icon: Lock },
    { value: "private-key" as AuthType, label: "Private key", icon: KeyRound }
  ];
  const keepaliveDefault = values.keepalive === DEFAULT_KEEPALIVE_SEC;

  return (
    <>
      <Modal
        open={open && !missing}
        onClose={requestClose}
        eyebrow="SSH servers"
        title={editing ? `Edit ${savedName}` : "Add server"}
        description={editing ? "Changes apply the next time you connect." : "Name, host, port and username are required to save. Sign-in details can follow later."}
        icon={Server}
        iconTone="busy"
        busy={saving}
        onSubmit={() => void save()}
        initialFocusRef={request.focus === "password" && usesPassword ? passwordRef : request.focus === "key" && !usesPassword ? keyPickerRef : undefined}
        footer={
          <>
            {saving ? <span className="modal-foot-note">Closing waits until saving is done.</span> : null}
            <Button disabled={saving} onClick={requestClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" busy={saving} busyLabel="Saving…">
              Save server
            </Button>
          </>
        }
      >
        <fieldset className="fm-fieldset" disabled={saving}>
          <legend className="sr-only">Server details</legend>

          {formError ? (
            <Callout tone="danger" title={formError.title} role="alert">
              {formError.message}
            </Callout>
          ) : null}

          {liveState ? (
            <Callout tone="info" title={`${savedName} is ${liveState === "connecting" ? "connecting" : liveState === "reconnecting" ? "reconnecting" : "connected"}`}>
              Edits apply from your next connect. The running session, including its automatic reconnects, keeps the settings it started with.
            </Callout>
          ) : null}

          <section className="fm-group" aria-labelledby={fieldId("g1")}>
            <GroupHead
              id={fieldId("g1")}
              number="01"
              title="Connection"
              aside={
                <span className="fm-preview" title="How this server reads in lists">
                  {connectionPreview(values)}
                </span>
              }
            />
            <div className="fm-conn">
              <Field label="Name" id={fieldId("name")} error={errors.name} className="fm-span">
                <TextInput value={values.name} placeholder="For example Frankfurt-01" autoComplete="off" onChange={(event) => update("name", event.target.value)} />
              </Field>
              <Field label="Host" id={fieldId("host")}>
                <TextInput
                  mono
                  value={values.host}
                  placeholder="203.0.113.10 or vps.example.net"
                  autoComplete="off"
                  autoCapitalize="off"
                  invalid={Boolean(errors.host)}
                  aria-describedby={errors.host ? fieldId("host-error") : undefined}
                  onChange={(event) => update("host", event.target.value)}
                />
              </Field>
              <Field label="Port" id={fieldId("port")}>
                <TextInput
                  mono
                  type="number"
                  min={1}
                  max={65535}
                  inputMode="numeric"
                  value={values.port}
                  invalid={Boolean(errors.port)}
                  aria-describedby={errors.port ? fieldId("port-error") : undefined}
                  onChange={(event) => update("port", event.target.value)}
                />
              </Field>
              {errors.host || errors.port ? (
                <div className="fm-span fm-errors">
                  {errors.host ? <FieldError id={fieldId("host-error")}>{errors.host}</FieldError> : null}
                  {errors.port ? <FieldError id={fieldId("port-error")}>{errors.port}</FieldError> : null}
                </div>
              ) : null}
              <Field label="Username" id={fieldId("username")} error={errors.username} className="fm-span">
                <TextInput mono value={values.username} placeholder="root" autoComplete="off" autoCapitalize="off" onChange={(event) => update("username", event.target.value)} />
              </Field>
            </div>
          </section>

          <section className="fm-group fm-group-signin" aria-labelledby={fieldId("g2")}>
            <GroupHead id={fieldId("g2")} number="02" title="Sign in" />
            <Segmented<AuthType> block ariaLabel="Sign-in method" value={values.authType} options={authOptions} onChange={(value) => update("authType", value)} />
            <div className="fm-swap anim-swap" key={values.authType}>
              {usesPassword ? (
                <Field
                  label="Password"
                  id={fieldId("password")}
                  labelAside={
                    editing ? (
                      passwordSaved ? (
                        <Badge tone="ok" icon={Check}>
                          Saved
                        </Badge>
                      ) : (
                        <Badge tone="warn">Not saved</Badge>
                      )
                    ) : undefined
                  }
                  after={
                    <>
                      {passwordState}
                      {linkedKey ? <Hint>{`Saving with Password unlinks ${linkedKey.name} from this server. You can pick it again any time.`}</Hint> : null}
                    </>
                  }
                >
                  <SecretInput
                    ref={passwordRef}
                    value={values.password}
                    onValueChange={(value) => update("password", value)}
                    secretName="password"
                    placeholder={editing ? (passwordSaved ? "Leave blank to keep the saved password" : "Type the server password") : "Server password"}
                    aria-describedby={fieldId("password-state")}
                  />
                </Field>
              ) : (
                <KeyPickerField
                  id={fieldId("key")}
                  keys={store.sshKeys}
                  configs={store.sshConfigs}
                  value={values.privateKeyId}
                  onChange={(keyId) => update("privateKeyId", keyId)}
                  onAddKey={openAddKey}
                  passwordStillSaved={passwordSaved}
                />
              )}
            </div>
          </section>

          <section className="fm-group" aria-labelledby={fieldId("g3")}>
            <GroupHead id={fieldId("g3")} number="03" title="Security" aside={<PinBadge state={pin} />} />
            <FingerprintField
              id={fieldId("fingerprint")}
              value={values.fingerprint}
              onChange={(value) => update("fingerprint", value)}
              onReveal={() => setFingerprintRevealed(true)}
              analysis={fingerprint}
              error={fingerprintError}
              pin={pin}
              serverName={displayName}
              suggestion={observed}
              device={deviceNoun(environment.platform)}
            />
          </section>

          <section className="fm-group fm-adv" data-open={advancedOpen ? "true" : "false"} aria-label="Advanced">
            <button
              type="button"
              className="fm-adv-btn"
              aria-expanded={advancedOpen}
              aria-controls={fieldId("advanced")}
              onClick={() => setAdvancedOpen((current) => !current)}
            >
              <span className="fm-group-title">
                <span className="fm-num">04</span>
                Advanced
              </span>
              <span className="fm-adv-sum">{advancedSummary(values)}</span>
              <Icon icon={ChevronDown} size="sm" className="chev faint" />
            </button>
            <Collapse open={advancedOpen} id={fieldId("advanced")}>
              <div className="fm-adv-inner">
                <Field
                  label="Keepalive"
                  id={fieldId("keepalive")}
                  labelAside={keepaliveDefault ? <Badge square>default</Badge> : undefined}
                  error={errors.keepalive}
                  keepHint
                  hint="How often Shadow checks the server is still there, so quiet sessions don't drop. 60–3600 seconds."
                >
                  <div className="fm-row-between">
                    <NumberStepper
                      value={values.keepalive}
                      onChange={(value) => update("keepalive", value)}
                      min={MIN_KEEPALIVE_SEC}
                      max={MAX_KEEPALIVE_SEC}
                      step={KEEPALIVE_STEP_SEC}
                      unit="s"
                      decrementLabel="30 seconds less"
                      incrementLabel="30 seconds more"
                    />
                    {!keepaliveDefault ? (
                      <button type="button" className="link-btn" onClick={() => update("keepalive", DEFAULT_KEEPALIVE_SEC)}>
                        Reset to {DEFAULT_KEEPALIVE_SEC} s
                      </button>
                    ) : null}
                  </div>
                </Field>
                <Field label="Note" optional id={fieldId("note")} hint="Private to you and shown only in this form.">
                  <TextArea
                    className="fm-note-area"
                    rows={3}
                    value={values.note}
                    placeholder="Anything worth remembering about this server"
                    spellCheck
                    onChange={(event) => update("note", event.target.value)}
                  />
                </Field>
              </div>
            </Collapse>
          </section>
        </fieldset>
      </Modal>
      <KeyFormModal
        request={keyForm}
        onClose={() => setKeyForm(null)}
        onSaved={(keyId) => {
          setValues((current) => ({ ...current, authType: "private-key", privateKeyId: keyId }));
        }}
      />
    </>
  );
}
