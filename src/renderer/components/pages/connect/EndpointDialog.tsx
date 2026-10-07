import { Clock, Globe, Lock, Radar, type LucideIcon } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { Badge, Button, Field, Icon, LinkButton, Modal, TextInput, type Tone } from "../../ui/index.js";
import {
  DEFAULT_CHECK_ENDPOINT,
  endpointError,
  looksLikeWebAddress,
  probeMethodCopy,
  probeMethodFor,
  type ProbeMethod
} from "./tunnel-check.js";

const METHOD_ICON: Record<ProbeMethod, LucideIcon> = { tls: Lock, http: Globe, wait: Clock };
const METHOD_TONE: Record<ProbeMethod, Tone> = { tls: "ok", http: "info", wait: "warn" };

export interface EndpointDialogProps {
  open: boolean;
  /** The saved endpoint the draft starts from. */
  current: string;
  onClose: () => void;
}

/**
 * "Check endpoint": where Run check sends its test request. Previews how the
 * port will be probed and rejects links and paths before they are saved.
 */
export function EndpointDialog({ open, current, onClose }: EndpointDialogProps): JSX.Element {
  const { run, toast } = useAppData();
  const [value, setValue] = useState(current);
  const [touched, setTouched] = useState(false);
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const methodId = useId();
  const hintId = useId();

  // Every opening starts from the saved value; Cancel drops the draft.
  useEffect(() => {
    if (open) {
      setValue(current);
      setTouched(false);
    }
    // Only a new opening resets the draft, not a saved value arriving meanwhile.
  }, [open]);

  const error = endpointError(value);
  const showError = error !== undefined && (touched || looksLikeWebAddress(value)) ? error : undefined;
  const probe = error === undefined ? probeMethodFor(value) : undefined;
  const method = probe ? probeMethodCopy(probe.method, probe.port) : undefined;
  const trimmed = value.trim();

  const save = async (): Promise<void> => {
    setTouched(true);
    if (error !== undefined) {
      inputRef.current?.focus();
      return;
    }
    if (trimmed === current) {
      onClose();
      return;
    }
    setSaving(true);
    const result = await run(() => api.updateSettings({ checkEndpoint: trimmed }), { errorTitle: "Couldn't save the endpoint" });
    setSaving(false);
    if (result) {
      toast({ tone: "success", title: "Endpoint saved", message: `The next check goes to ${trimmed}. No need to reconnect.` });
      onClose();
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      busy={saving}
      icon={Radar}
      iconTone="busy"
      eyebrow="Tunnel check"
      title="Check endpoint"
      description="Where Run check sends its test request. The next check uses it — no need to reconnect."
      initialFocusRef={inputRef}
      onSubmit={() => void save()}
      footer={
        <>
          <Button disabled={saving} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" busy={saving} busyLabel="Saving…" disabled={!trimmed || showError !== undefined}>
            Save
          </Button>
        </>
      }
    >
      <Field
        label="Endpoint"
        error={showError}
        labelAside={
          trimmed !== DEFAULT_CHECK_ENDPOINT ? (
            <LinkButton
              icon={null}
              disabled={saving}
              onClick={() => {
                setValue(DEFAULT_CHECK_ENDPOINT);
                setTouched(false);
                inputRef.current?.focus();
              }}
            >
              Reset to {DEFAULT_CHECK_ENDPOINT}
            </LinkButton>
          ) : null
        }
      >
        <TextInput
          ref={inputRef}
          icon={Globe}
          mono
          value={value}
          placeholder="host:port"
          autoComplete="off"
          autoCapitalize="off"
          disabled={saving}
          aria-describedby={`${method ? methodId : ""} ${hintId}`.trim()}
          onChange={(event) => setValue(event.target.value)}
          onBlur={() => setTouched(trimmed.length > 0)}
        />
      </Field>

      {probe && method ? (
        <div className="cn-method anim-swap" key={`${probe.method}-${probe.port}`} id={methodId}>
          <span className="card-icon">
            <Icon icon={METHOD_ICON[probe.method]} size="sm" />
          </span>
          <div className="cn-method-copy">
            <span className="row-wrap cn-method-head">
              <span className="eyebrow">How it’s checked</span>
              <Badge tone={METHOD_TONE[probe.method]}>{method.label}</Badge>
            </span>
            <span>{method.text}</span>
          </div>
        </div>
      ) : null}

      <p className="hint" id={hintId}>
        TLS ports 443, 8443, 993 and 995 get a TLS handshake. HTTP ports 80, 8080 and 8000 get HEAD /. Any other port waits up to 12 s for the server to
        speak first.
      </p>
    </Modal>
  );
}
