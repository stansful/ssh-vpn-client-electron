import { ChevronRight, FileText, FolderOpen, LogOut, RotateCcw, type LucideIcon } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { api } from "../../api.js";
import { describeError } from "../../lib/errors.js";
import { useToasts } from "../../hooks/useToasts.js";
import type { AppSnapshot, StorageHealth } from "../../../shared/types.js";
import { Badge } from "../ui/Badge.js";
import { DisclosureButton } from "../ui/Button.js";
import { Callout } from "../ui/Callout.js";
import { IconTile } from "../ui/Card.js";
import { Collapse, KeyValue } from "../ui/Display.js";
import { Icon, Spinner } from "../ui/Icon.js";

type UnreadableHealth = Extract<StorageHealth, { state: "unreadable" }>;

function fileName(path: string): string {
  return path.split(/[\\/]/u).pop() || path;
}

/** "app-store.v1.json" → "app-store.v1.unreadable-…json", the backup name Start fresh uses. */
export function backupNameFor(storePath: string): string {
  const name = fileName(storePath);
  const base = name.replace(/\.json$/iu, "");
  return `${base}.unreadable-<date>.json`;
}

/**
 * Replaces the silent empty start when saved data can't be read: nothing
 * was overwritten, and nothing saves or auto-connects until the user picks
 * Open data folder, Start fresh (keeps a backup) or Quit.
 */
export function DataRecoveryScreen({ health, onRecovered }: { health: UnreadableHealth; onRecovered: (snapshot: AppSnapshot) => void }): JSX.Element {
  const { toast } = useToasts();
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [working, setWorking] = useState<"fresh" | "folder" | "quit" | undefined>();
  const detailsId = useId();

  const reportError = (title: string, error: unknown): void => {
    const described = describeError(error, { title });
    toast({ tone: "error", title: described.title, message: described.message, details: described.technical });
  };

  const openFolder = (): void => {
    setWorking("folder");
    void api
      .openDataFolder()
      .then((opened) => {
        if (!opened) {
          toast({ tone: "error", title: "Couldn't open the data folder", message: `Open ${health.dataDirectory} yourself.` });
        }
      })
      .catch((error: unknown) => reportError("Couldn't open the data folder", error))
      .finally(() => setWorking(undefined));
  };

  const startFresh = (): void => {
    setWorking("fresh");
    void api
      .recoverStorage("start-fresh")
      .then((snapshot) => {
        toast({ tone: "success", title: "Started fresh", message: "The unreadable data was kept as a backup in the data folder." });
        onRecovered(snapshot);
      })
      .catch((error: unknown) => {
        reportError("Couldn't start fresh", error);
        setWorking(undefined);
      });
  };

  const quit = (): void => {
    setWorking("quit");
    void api.quitApp().catch((error: unknown) => {
      reportError("Couldn't quit", error);
      setWorking(undefined);
    });
  };

  return (
    <main className="sys-screen">
      <div className="recovery-host">
        <div className="recovery rise">
          <div className="recovery-col">
            <div className="recovery-head">
              <IconTile icon={FileText} tone="warn" />
              <div className="stack-sm" role="alert">
                <span className="eyebrow">Data recovery</span>
                <h1 className="splash-title">Your saved data couldn’t be read</h1>
                <p className="splash-text">Shadow found its data file but couldn’t open it, so it stopped before changing anything.</p>
              </div>
            </div>
            <Callout tone="ok" title="Nothing was overwritten">
              Your servers, keys, profiles and rules are still in the file. Shadow won’t save anything or auto-connect until you choose.
            </Callout>
            <div className="stack-sm">
              <DisclosureButton open={detailsOpen} controls={detailsId} className="recovery-toggle" onClick={() => setDetailsOpen((current) => !current)}>
                What couldn’t be read
              </DisclosureButton>
              <Collapse open={detailsOpen} id={detailsId}>
                <KeyValue
                  className="recovery-kv"
                  items={[
                    { term: "File", value: health.storePath, mono: true },
                    { term: "Problem", value: health.message, mono: true },
                    { term: "Logged as", value: "Storage initialization failed", mono: true }
                  ]}
                />
              </Collapse>
            </div>
          </div>

          <div className="recovery-col">
            <span className="eyebrow">What to do</span>
            <div className="recovery-opts" role="group" aria-label="What to do with the unreadable data">
              <RecoveryOption
                icon={FolderOpen}
                title="Open data folder"
                description="Check the file or put back a copy you trust, then open Shadow again."
                busy={working === "folder"}
                disabled={working !== undefined}
                onClick={openFolder}
              />
              <RecoveryOption
                icon={RotateCcw}
                title={
                  <>
                    {working === "fresh" ? "Starting fresh…" : "Start fresh"}
                    <Badge tone="ok" square>
                      keeps a backup
                    </Badge>
                  </>
                }
                description={
                  health.secretsOnly ? (
                    <>
                      Renames the file to <span className="mono">{backupNameFor(health.storePath)}</span>. Servers, rules and settings stay; you add saved passwords, keys and profiles again.
                    </>
                  ) : (
                    <>
                      Renames the file to <span className="mono">{backupNameFor(health.storePath)}</span> and opens Shadow empty. You add servers and rules again.
                    </>
                  )
                }
                busy={working === "fresh"}
                disabled={working !== undefined}
                onClick={startFresh}
              />
              <RecoveryOption
                icon={LogOut}
                title="Quit"
                description="Close Shadow and leave everything as it is."
                busy={working === "quit"}
                disabled={working !== undefined}
                onClick={quit}
              />
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

function RecoveryOption({
  icon,
  title,
  description,
  busy,
  disabled,
  onClick
}: {
  icon: LucideIcon;
  title: ReactNode;
  description: ReactNode;
  busy: boolean;
  disabled: boolean;
  onClick: () => void;
}): JSX.Element {
  return (
    <button type="button" className="recovery-opt" disabled={disabled} aria-busy={busy || undefined} onClick={onClick}>
      <span className="card-icon">{busy ? <Spinner size="md" /> : <Icon icon={icon} />}</span>
      <span className="recovery-opt-main">
        <span className="recovery-opt-title">{title}</span>
        <span className="recovery-opt-desc">{description}</span>
      </span>
      <Icon icon={ChevronRight} size="sm" />
    </button>
  );
}
