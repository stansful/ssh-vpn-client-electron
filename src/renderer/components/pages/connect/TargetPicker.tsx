import { ArrowRight, ListPlus, Plus } from "lucide-react";
import { useMemo } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import type { GlobalTab } from "../../../../shared/types.js";
import { plural, protocolKeywords } from "../../../lib/format.js";
import { Badge, Icon, ListboxAction, Select, type ListboxOption } from "../../ui/index.js";
import { HYSTERIA2_INSECURE_PROFILE_WARNING, HYSTERIA2_INSECURE_TAG } from "../profiles/link-preview.js";
import { profileTarget, sshTarget, type ConnectTarget, type TargetState } from "./connect-target.js";

export interface TargetPickerProps {
  transport: GlobalTab;
  state: TargetState;
  /** A session runs or is starting on this transport: show it, don't let it change. */
  locked: boolean;
  /** Extra words for the trigger's accessible name ("unsupported"). */
  describedBy?: string;
}

const UNSUPPORTED_REASON = {
  security: "Unsupported security — can’t connect",
  transport: "Unsupported transport — can’t connect"
} as const;

/** "insecure=1": the link asks to skip certificate checks without a pin. It still connects, so it's a mark, not a block. */
function InsecureBadge(): JSX.Element {
  return (
    <Badge tone="warn" square title={HYSTERIA2_INSECURE_PROFILE_WARNING}>
      {HYSTERIA2_INSECURE_TAG}
    </Badge>
  );
}

function pickerLabel(transport: GlobalTab, target: ConnectTarget | undefined, locked: boolean): string {
  const noun = transport === "ssh" ? "SSH server" : "Xray profile";
  if (!target) {
    return `Choose ${noun}`;
  }
  if (locked) {
    return `${noun} locked: ${target.name}${targetMarks(target)}`;
  }
  return `Choose ${noun}, current: ${target.name}${targetMarks(target)}`;
}

/** What the trigger's badge says, for its accessible name: ", unsupported" or ", insecure=1: certificate checks stay on". */
function targetMarks(target: ConnectTarget): string {
  if (target.unsupported) {
    return ", unsupported";
  }
  return target.insecureWithoutPin ? `, ${HYSTERIA2_INSECURE_TAG}: certificate checks stay on` : "";
}

/**
 * Server/profile picker in the hero (`.picker` + listbox with search). The
 * first run shows a dashed "Add your first server" step instead.
 */
export function TargetPicker({ transport, state, locked, describedBy }: TargetPickerProps): JSX.Element {
  const { store, run, navigate } = useAppData();
  const ssh = transport === "ssh";

  const options = useMemo<Array<ListboxOption<string>>>(() => {
    if (ssh) {
      return store.sshConfigs.map((config) => {
        const target = sshTarget(config);
        return { value: config.id, label: config.name, sub: target.sub, lead: target.initials, keywords: config.host };
      });
    }
    const pinned = store.proxyProfiles.filter((profile) => profile.isPinned);
    const grouped = pinned.length > 0 && pinned.length < store.proxyProfiles.length;
    const ordered = grouped ? [...pinned, ...store.proxyProfiles.filter((profile) => !profile.isPinned)] : store.proxyProfiles;
    return ordered.map((profile) => {
      const target = profileTarget(profile);
      return {
        value: profile.id,
        label: profile.name,
        sub: target.sub,
        lead: target.initials,
        group: grouped ? (profile.isPinned ? "Pinned" : "Other profiles") : undefined,
        // The sub line already reads "Hysteria 2 · host:443,20000-30000 · quic · tls"; add the scheme names and stored transport.
        keywords: `${protocolKeywords(profile.protocol)} ${profile.transport} ${profile.security}`,
        disabled: Boolean(target.unsupported),
        disabledReason: target.unsupported ? UNSUPPORTED_REASON[target.unsupported] : undefined,
        badge:
          target.stale || target.insecureWithoutPin ? (
            <>
              {target.stale ? (
                <Badge tone="warn" square>
                  Gone from source
                </Badge>
              ) : null}
              {target.insecureWithoutPin ? <InsecureBadge /> : null}
            </>
          ) : undefined
      };
    });
  }, [ssh, store.proxyProfiles, store.sshConfigs]);

  if (state.noneSaved) {
    return (
      <button
        type="button"
        className="picker cn-picker-empty"
        onClick={() => navigate(ssh ? "servers" : "profiles", ssh ? { type: "new-server" } : { type: "add-profile" })}
      >
        <span className="avatar" aria-hidden="true">
          <Icon icon={Plus} size="sm" />
        </span>
        <span className="picker-main">
          <span className="picker-title">{ssh ? "Add your first server" : "Add your first profile"}</span>
          <span className="picker-sub">{ssh ? "Address, user, password or key" : "Paste a VLESS, VMess, Trojan or Hysteria 2 link"}</span>
        </span>
        <Icon icon={ArrowRight} size="sm" className="faint" />
      </button>
    );
  }

  const { target } = state;
  const select = (id: string): void => {
    void run(() => (ssh ? api.selectConfig(id) : api.selectProxyProfile(id)), {
      errorTitle: ssh ? "Couldn't choose the server" : "Couldn't choose the profile",
      background: true
    });
  };

  return (
    <Select
      value={target?.id}
      options={options}
      onChange={select}
      ariaLabel={ssh ? "SSH servers" : "Xray profiles"}
      triggerAriaLabel={pickerLabel(transport, target, locked)}
      triggerClassName="picker"
      locked={locked}
      searchPlaceholder={ssh ? "Search servers" : "Search profiles"}
      aria-describedby={describedBy}
      footer={(close) =>
        ssh ? (
          <ListboxAction
            icon={Plus}
            onClick={() => {
              close();
              navigate("servers", { type: "new-server" });
            }}
          >
            Add server
          </ListboxAction>
        ) : (
          <>
            <ListboxAction
              icon={Plus}
              onClick={() => {
                close();
                navigate("profiles", { type: "add-profile" });
              }}
            >
              Add profile
            </ListboxAction>
            <ListboxAction
              icon={ListPlus}
              onClick={() => {
                close();
                navigate("profiles", { type: "import-profiles" });
              }}
            >
              Import links
            </ListboxAction>
          </>
        )
      }
      renderTrigger={() =>
        target ? (
          <>
            <span className="avatar" aria-hidden="true">
              {target.initials}
            </span>
            <span className="picker-main">
              <span className="picker-title">{target.name}</span>
              {target.sub ? <span className="picker-sub">{target.sub}</span> : null}
            </span>
            {target.unsupported ? (
              <Badge tone="warn" square>
                Unsupported
              </Badge>
            ) : target.insecureWithoutPin ? (
              <InsecureBadge />
            ) : null}
          </>
        ) : (
          <>
            <span className="avatar" aria-hidden="true">
              ?
            </span>
            <span className="picker-main">
              <span className="picker-title">{ssh ? "Choose a server" : "Choose a profile"}</span>
              <span className="picker-sub cn-picker-count">{plural(state.count, ssh ? "server" : "profile")} saved</span>
            </span>
          </>
        )
      }
    />
  );
}
