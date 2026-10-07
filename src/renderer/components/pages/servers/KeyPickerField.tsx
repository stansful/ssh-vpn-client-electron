import { KeyRound, Plus, TriangleAlert } from "lucide-react";
import { useId, useMemo } from "react";
import { cx, Badge, Hint, Icon, ListboxAction, Select, StateLine, type ListboxOption } from "../../ui/index.js";
import { keyOptionSub, keySupportIssue } from "../keys/key-model.js";
import type { SshConfig, SshKeyMetadata } from "../../../../shared/types.js";

export interface KeyPickerFieldProps {
  keys: readonly SshKeyMetadata[];
  configs: readonly SshConfig[];
  value: string;
  onChange: (keyId: string) => void;
  /** Opens the key form on top of the server form. */
  onAddKey: () => void;
  /** The saved server still has a password stored (kept while it signs in with a key). */
  passwordStillSaved: boolean;
  id?: string;
}

/**
 * Key picker of the server form: each key shows its type, passphrase state,
 * Key ID and who uses it, so two keys with one name never look alike.
 */
export function KeyPickerField({ keys, configs, value, onChange, onAddKey, passwordStillSaved, id }: KeyPickerFieldProps): JSX.Element {
  const generated = useId();
  const stateId = `${generated}-state`;
  const options = useMemo<Array<ListboxOption<string>>>(
    () =>
      keys.map((key) => {
        const issue = keySupportIssue(key);
        return {
          value: key.id,
          label: key.name,
          sub: keyOptionSub(key, configs),
          lead: <Icon icon={KeyRound} size="sm" />,
          badge: issue ? (
            <Badge tone="warn" title={issue}>
              Can’t sign in yet
            </Badge>
          ) : undefined
        };
      }),
    [configs, keys]
  );
  const selected = keys.find((key) => key.id === value);
  const issue = selected ? keySupportIssue(selected) : undefined;
  const countLine = keys.length === 0 ? "No keys in SSH keys yet" : `${keys.length} ${keys.length === 1 ? "key" : "keys"} in SSH keys`;

  return (
    <div className="field">
      <span className="label" aria-hidden="true">
        Private key
      </span>
      <Select<string>
        id={id}
        value={selected ? value : undefined}
        options={options}
        onChange={onChange}
        ariaLabel="Saved keys"
        triggerAriaLabel={`Private key: ${selected ? selected.name : "none chosen"}`}
        triggerClassName="select-btn fm-pick"
        searchPlaceholder="Search keys"
        emptyText="No keys yet. Add one below."
        aria-describedby={!selected || issue ? stateId : undefined}
        renderTrigger={(option) => (
          <>
            <span className="fm-key-av" data-filled={option ? "true" : "false"}>
              <Icon icon={KeyRound} size="sm" />
            </span>
            <span className="picker-main">
              <span className={cx("picker-title", !option && "is-placeholder")}>{option ? option.label : "Choose a saved key"}</span>
              <span className="picker-sub">{option ? option.sub : countLine}</span>
            </span>
          </>
        )}
        footer={(close) => (
          <ListboxAction
            icon={Plus}
            onClick={() => {
              close();
              // Let the menu hand focus back to the picker first, so closing
              // the key form returns there.
              window.requestAnimationFrame(() => window.requestAnimationFrame(onAddKey));
            }}
          >
            Add a new key…
          </ListboxAction>
        )}
      />
      <div className="fm-row-between">
        <span className="hint">Keys show their type and Key ID, so two keys with one name never look alike.</span>
        <button type="button" className="link-btn" onClick={onAddKey}>
          <Icon icon={Plus} />
          Add a new key
        </button>
      </div>
      {!selected ? (
        <StateLine tone="warn" icon={TriangleAlert} id={stateId}>
          <b>No key chosen</b> — connecting will stop at sign-in until you pick one.
        </StateLine>
      ) : issue ? (
        <StateLine tone="warn" icon={TriangleAlert} id={stateId}>
          <b>{issue}</b> Pick an RSA or Ed25519 key, or replace this one in SSH keys.
        </StateLine>
      ) : null}
      {passwordStillSaved ? <Hint>Your saved password stays stored. Switch back to Password to use it again.</Hint> : null}
    </div>
  );
}
