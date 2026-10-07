import { Check, Link, TriangleAlert, Zap } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type ClipboardEvent } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { describeError } from "../../../lib/errors.js";
import { formatProfileSummary } from "../../../lib/format.js";
import { proxyProtocolMark } from "../../../../shared/proxy-protocols.js";
import type { ProxyProfile } from "../../../../shared/types.js";
import { Avatar, Badge, Button, Callout, cx, Field, LinkButton, Modal, TextInput } from "../../ui/index.js";
import { applySchemeFix, describeLinkProblem, linkFingerprint, previewShareLink, suggestScheme, type LinkPreview } from "./link-preview.js";
import { isProfileLimitError } from "./import-lines.js";
import { DIALOG_EXIT_MS, fixedInsecureCopy, insecureProfileFixedBy, savedProfileCopy, unsupportedPart } from "./profile-presenter.js";

export interface AddProfileDialogProps {
  open: boolean;
  onClose: () => void;
  /** Switch to Import links, optionally carrying pasted links over. */
  onOpenImport: (text?: string) => void;
}

/** Links on separate lines, ignoring blanks and # comments. */
function countLinks(text: string): number {
  return text.split(/\r?\n/u).filter((line) => {
    const trimmed = line.trim();
    return trimmed !== "" && !trimmed.startsWith("#");
  }).length;
}

/** The saved profile that has the same link, found by fingerprint like the main process does. */
function useSavedTwin(link: LinkPreview | undefined, profiles: readonly ProxyProfile[]): ProxyProfile | undefined {
  const [match, setMatch] = useState<{ canonical: string; profile?: ProxyProfile }>();
  const canonical = link?.canonical;
  useEffect(() => {
    if (!canonical) {
      setMatch(undefined);
      return undefined;
    }
    let active = true;
    void linkFingerprint({ canonical }).then((fingerprint) => {
      if (active) {
        setMatch({ canonical, profile: fingerprint ? profiles.find((profile) => profile.fingerprint === fingerprint) : undefined });
      }
    });
    return () => {
      active = false;
    };
  }, [canonical, profiles]);
  return match && match.canonical === canonical ? match.profile : undefined;
}

/**
 * Add Xray profile (Dialogs.dc.html): one single-line link, previewed as it
 * will be saved. The draft survives closing the dialog while the page is open.
 */
export function AddProfileDialog({ open, onClose, onOpenImport }: AddProfileDialogProps): JSX.Element {
  const { store, run, toast } = useAppData();
  const [link, setLink] = useState("");
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string>();
  const [pasted, setPasted] = useState<{ text: string; count: number }>();
  const storeRef = useRef(store);
  storeRef.current = store;
  const previewId = useId();
  const resetTimer = useRef<number>();
  useEffect(() => () => window.clearTimeout(resetTimer.current), []);

  const preview = useMemo(() => previewShareLink(link), [link]);
  const parsed = preview.status === "ok" ? preview.link : undefined;
  const twin = useSavedTwin(parsed, store.proxyProfiles);
  // A pinned link for the selected insecure=1 profile's server is another profile; select it instead.
  const fixes = insecureProfileFixedBy(parsed, store);
  const typo = preview.status === "error" ? suggestScheme(link) : undefined;
  const typoFixReads = typo ? previewShareLink(applySchemeFix(link, typo.to)).status === "ok" : false;
  const bad = parsed ? unsupportedPart(parsed) : undefined;

  let error: string | undefined;
  if (pasted) {
    error = `You pasted ${pasted.count} links. Add profile saves one link; Import links adds them all at once.`;
  } else if (saveError) {
    error = saveError;
  } else if (preview.status === "error" && touched) {
    error = describeLinkProblem(link, preview.message);
  }

  let namePlaceholder = "Taken from the link if empty";
  if (twin) {
    namePlaceholder = `${twin.name}, kept from your library`;
  } else if (parsed) {
    namePlaceholder = `${parsed.name}, from the link`;
  }

  const changeLink = (value: string): void => {
    setLink(value);
    setPasted(undefined);
    setSaveError(undefined);
  };

  const handlePaste = (event: ClipboardEvent<HTMLInputElement>): void => {
    const text = event.clipboardData.getData("text");
    setTouched(true);
    // A single-line field would glue several links into one; offer Import links instead.
    if (countLinks(text) > 1) {
      event.preventDefault();
      setPasted({ text, count: countLinks(text) });
    }
  };

  const save = async (): Promise<void> => {
    if (saving) {
      return;
    }
    if (!parsed) {
      setTouched(link.trim() !== "");
      return;
    }
    setSaving(true);
    setSaveError(undefined);
    const before = storeRef.current;
    // An empty name would replace a saved profile's name with the link's; keep the one you gave it.
    const nameToSave = name.trim() || twin?.name || "";
    try {
      const next = await run(() => api.upsertProxyProfile({ name: nameToSave, rawUri: link.trim(), source: "manual" }), { silent: true, rethrow: true });
      if (next) {
        const known = new Set(before.proxyProfiles.map((profile) => profile.id));
        const saved = next.store.proxyProfiles.find((profile) => !known.has(profile.id) || profile.id === twin?.id);
        const tagged = fixes && saved && saved.id !== fixes.id && next.store.selectedProxyProfileId === fixes.id ? fixes : undefined;
        const switched =
          tagged && saved
            ? await run(() => api.selectProxyProfile(saved.id), { errorTitle: "Couldn’t choose the saved profile", background: true })
            : undefined;
        toast(
          switched && tagged && saved
            ? { tone: "success", title: "Profile saved", message: fixedInsecureCopy(tagged, saved) }
            : { tone: "success", ...savedProfileCopy(before, next.store) }
        );
        onClose();
        // Start the next draft clean, once the dialog has finished closing.
        window.clearTimeout(resetTimer.current);
        resetTimer.current = window.setTimeout(() => {
          setLink("");
          setName("");
          setTouched(false);
        }, DIALOG_EXIT_MS);
      }
    } catch (failure) {
      setSaveError(
        isProfileLimitError(failure)
          ? "Your library already holds 10,000 profiles, the most it can keep. Remove profiles you don’t use, then save this one."
          : describeError(failure).message
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      busy={saving}
      icon={Zap}
      iconTone="busy"
      eyebrow="Xray profiles"
      title="Add Xray profile"
      description="Paste one share link from your provider. VLESS, VMess, Trojan and Hysteria 2 links work."
      onSubmit={() => {
        void save();
      }}
      footer={
        <>
          <Button disabled={saving} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" busy={saving} busyLabel="Saving…" disabled={!parsed}>
            Save profile
          </Button>
        </>
      }
    >
      <Field label="Share link" error={error} disabled={saving}>
        <TextInput
          icon={Link}
          mono
          value={link}
          placeholder="vless://…, vmess://…, trojan://… or hysteria2://…"
          autoComplete="off"
          autoCapitalize="off"
          aria-describedby={parsed ? previewId : undefined}
          onChange={(event) => changeLink(event.target.value)}
          onPaste={handlePaste}
          onBlur={() => setTouched(link.trim() !== "")}
        />
      </Field>

      {typo && error && !pasted && !saveError ? (
        <div className="pf-row-between pf-fix-row anim-swap">
          <span className="hint">{typoFixReads ? "The rest of the link looks fine." : ""}</span>
          <Button size="sm" onClick={() => changeLink(applySchemeFix(link, typo.to))}>
            Change to {typo.to}://
          </Button>
        </div>
      ) : null}

      {parsed ? (
        <div className="stack-sm anim-swap" id={previewId} key={parsed.canonical}>
          <span className="eyebrow">Found in the link</span>
          <div className={cx("pf-detect", bad && "is-warn")}>
            <Avatar>{proxyProtocolMark(parsed.protocol)}</Avatar>
            <div className="item-main">
              <span className="item-title">
                <span className="truncate">{parsed.name}</span>
              </span>
              <span className="item-sub">
                <span className="mono">{formatProfileSummary(parsed)}</span>
              </span>
            </div>
            {bad ? (
              <Badge tone="warn" icon={TriangleAlert}>
                Can’t connect
              </Badge>
            ) : (
              <Badge tone="ok" icon={Check}>
                Ready
              </Badge>
            )}
          </div>
          {bad ? (
            <span className="hint">
              Xray doesn’t recognize its {bad === "security" ? "security mode" : "transport"}, so you can save it but not connect with it.
            </span>
          ) : null}
          {parsed.warnings?.map((warning) => (
            <Callout key={warning} tone="warn">
              {warning}
            </Callout>
          ))}
          {twin ? (
            <span className="hint">
              Already in your library as {twin.name}. Saving updates it and keeps its pin{twin.id === store.selectedProxyProfileId ? " and selection" : ""}.
            </span>
          ) : null}
          {fixes ? <span className="hint">{fixedInsecureCopy(fixes)}</span> : null}
        </div>
      ) : null}

      <Field label="Name" optional disabled={saving}>
        <TextInput value={name} placeholder={namePlaceholder} autoComplete="off" onChange={(event) => setName(event.target.value)} />
      </Field>

      <div className="pf-row-between">
        <span className="hint">Got several links? Use Import links instead.</span>
        <LinkButton
          disabled={saving}
          onClick={() => {
            const text = pasted?.text;
            setPasted(undefined);
            onOpenImport(text);
          }}
        >
          Import links
        </LinkButton>
      </div>
    </Modal>
  );
}
