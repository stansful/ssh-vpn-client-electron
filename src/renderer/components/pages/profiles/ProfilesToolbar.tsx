import { ClipboardPaste, Globe, Link, RefreshCw, Trash2, Zap } from "lucide-react";
import type { ReactNode } from "react";
import { Button, Card, Collapse, cx, Icon, IconTile, Progress, SearchInput, Segmented, Spinner, type SegmentedOption } from "../../ui/index.js";
import type { ProfileCounts, ProfileFilter } from "./profile-presenter.js";

export interface ProfilesToolbarProps {
  query: string;
  onQueryChange: (query: string) => void;
  filter: ProfileFilter;
  onFilterChange: (filter: ProfileFilter) => void;
  counts: ProfileCounts;
  publicMeta: { text: string; error: boolean };
  refreshing: boolean;
  /** Something else (a removal) is running. */
  busy: boolean;
  onRefresh: () => void;
  onRemoveUnpinned: () => void;
}

/** Search, the All / Pinned / Gone filter, the public list and Remove unpinned. */
export function ProfilesToolbar({
  query,
  onQueryChange,
  filter,
  onFilterChange,
  counts,
  publicMeta,
  refreshing,
  busy,
  onRefresh,
  onRemoveUnpinned
}: ProfilesToolbarProps): JSX.Element {
  const options: Array<SegmentedOption<ProfileFilter>> = [
    { value: "all", label: "All", count: counts.all },
    { value: "pinned", label: "Pinned", count: counts.pinned },
    {
      value: "gone",
      // One flex item, so the segment's gap doesn't split the words.
      label: (
        <span>
          Gone<span className="pf-long"> from source</span>
        </span>
      ),
      count: counts.gone
    }
  ];
  const removeDisabled = busy || refreshing || counts.unpinned === 0;
  return (
    <Card className="pf-toolbar" rise={1} aria-label="Find and manage profiles">
      <div className="pf-tool-row">
        <div className="pf-search">
          <SearchInput
            value={query}
            onValueChange={onQueryChange}
            aria-label="Search Xray profiles"
            placeholder="Search name, host, protocol, transport"
            autoComplete="off"
          />
        </div>
        <Segmented size="sm" className="pf-seg" ariaLabel="Show" value={filter} options={options} onChange={onFilterChange} />
      </div>

      <hr className="divider" />

      <div className="pf-tool-row">
        <div className="pf-public">
          <IconTile icon={Globe} tone="info" />
          <div className="pf-public-copy" aria-live="polite">
            <span className="pf-public-title">Public list</span>
            <span className={cx("pf-public-meta", publicMeta.error && "is-error")}>{publicMeta.text}</span>
          </div>
          <Button size="sm" icon={RefreshCw} busy={refreshing} busyLabel="Refreshing…" disabled={busy} onClick={onRefresh}>
            Refresh public list
          </Button>
        </div>
        <Button
          size="sm"
          variant="danger-ghost"
          icon={Trash2}
          className="pf-danger-ghost"
          disabled={removeDisabled}
          title={counts.unpinned === 0 ? "Every profile is pinned" : `Remove all ${counts.unpinned} unpinned profiles`}
          onClick={onRemoveUnpinned}
        >
          Remove unpinned…
        </Button>
      </div>

      <Collapse open={refreshing} className="pf-prog-wrap">
        <Progress label="Refreshing the public list" className="pf-progress" />
      </Collapse>
    </Card>
  );
}

export interface ProfilesOnboardingProps {
  refreshing: boolean;
  onAdd: () => void;
  onImport: () => void;
  onRefresh: () => void;
}

/** Empty library: three ways to get the first profiles. */
export function ProfilesOnboarding({ refreshing, onAdd, onImport, onRefresh }: ProfilesOnboardingProps): JSX.Element {
  return (
    <Card className="pf-onboard" rise={1} aria-label="No profiles yet">
      <div className="pf-onboard-copy">
        <IconTile icon={Zap} tone="busy" />
        <h2 className="pf-onboard-title">No Xray profiles yet</h2>
        <p>A profile is a VLESS, VMess, Trojan or Hysteria 2 share link. Add the ones you trust and pick one for Connect. Links stay encrypted on this device.</p>
      </div>
      <div className="pf-options">
        <OnboardingOption icon={<Icon icon={Link} />} title="Add one link" onClick={onAdd}>
          Paste a single vless://, vmess://, trojan:// or hysteria2:// link and give it a name.
        </OnboardingOption>
        <OnboardingOption icon={<Icon icon={ClipboardPaste} />} title="Import a batch" onClick={onImport}>
          Paste many links at once, one per line. Links you already have are updated, not duplicated.
        </OnboardingOption>
        <OnboardingOption
          icon={refreshing ? <Spinner size="md" /> : <Icon icon={Globe} />}
          title={refreshing ? "Loading the public list…" : "Load the public list"}
          disabled={refreshing}
          busy={refreshing}
          onClick={onRefresh}
        >
          Free profiles from a fixed public source. Use them only if you trust that source.
        </OnboardingOption>
      </div>
    </Card>
  );
}

function OnboardingOption({
  icon,
  title,
  children,
  onClick,
  disabled,
  busy
}: {
  icon: ReactNode;
  title: string;
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  busy?: boolean;
}): JSX.Element {
  return (
    <button type="button" className="pf-option" disabled={disabled} aria-busy={busy || undefined} onClick={onClick}>
      <span className="card-icon">{icon}</span>
      <span className="pf-option-title">{title}</span>
      <span className="pf-option-text">{children}</span>
    </button>
  );
}
