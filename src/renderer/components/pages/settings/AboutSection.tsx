import { Copy, ExternalLink, FolderOpen, Github } from "lucide-react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { platformArchLabel } from "../../../lib/format.js";
import { GITHUB_REPOSITORY_URL } from "../../../../shared/links.js";
import { buttonClass, Card, CopyButton, Icon, IconButton, useCopyFeedback } from "../../ui/index.js";
import { secretsCopy, sectionElementId } from "./settings-model.js";

const GITHUB_DISPLAY = GITHUB_REPOSITORY_URL.replace(/^https:\/\//u, "");

export function AboutSection(): JSX.Element {
  const { environment, run, toast } = useAppData();
  const { copied, copy } = useCopyFeedback();
  const secrets = secretsCopy(environment.secretsBackend);

  const copyGitHub = async (): Promise<void> => {
    if (await copy(GITHUB_REPOSITORY_URL)) {
      toast({ id: "github-link-copied", tone: "success", title: "GitHub link copied", message: GITHUB_DISPLAY });
    }
  };

  return (
    <Card id={sectionElementId("about")} className="st-section" rise={7} aria-labelledby="st-about-h" tabIndex={-1}>
      <div className="st-about-top">
        <span className="st-mark">
          <img src="./icon.svg" alt="" />
        </span>
        <div className="st-about-id">
          <h2 className="st-about-name" id="st-about-h">
            Shadow SSH
          </h2>
          <span className="mono muted">
            {environment.version} · {platformArchLabel(environment.platform, environment.arch)}
          </span>
        </div>
      </div>
      <p className="card-sub st-about-sub">
        Sends the apps, sites and IPs you choose through your own SSH server or Xray profile. Everything else stays direct.
      </p>

      <div className="st-rows">
        <div className="st-r">
          <span className="st-r-label">Source code</span>
          <span className="st-r-value">
            <span className="mono truncate" title={GITHUB_REPOSITORY_URL}>
              {GITHUB_DISPLAY}
            </span>
          </span>
          <span className="st-r-actions">
            <IconButton icon={Copy} label="Copy GitHub link" tooltip={copied ? "Copied" : "Copy link"} done={copied} onClick={() => void copyGitHub()} />
            <button
              type="button"
              className={buttonClass("secondary", "sm")}
              onClick={() => void run(() => api.openExternal(GITHUB_REPOSITORY_URL), { errorTitle: "Couldn't open GitHub" })}
            >
              <Icon icon={Github} size="sm" />
              Open on GitHub
              <Icon icon={ExternalLink} size="sm" className="faint" />
            </button>
          </span>
        </div>

        <div className="st-r">
          <span className="st-r-label">Data folder</span>
          <span className="st-r-value">
            <span className="mono break">{environment.dataDirectory}</span>
            <span className="hint">Settings, servers, keys, logs and downloaded updates live here.</span>
          </span>
          <span className="st-r-actions">
            <CopyButton text={environment.dataDirectory} label="Copy data folder path" />
            <IconButton
              icon={FolderOpen}
              label="Open data folder"
              onClick={() => void run(() => api.openDataFolder(), { errorTitle: "Couldn't open the data folder" })}
            />
          </span>
        </div>

        <div className="st-r">
          <span className="st-r-label">Secrets</span>
          <span className="st-r-value">
            <span>{secrets.title}</span>
            <span className="hint">{secrets.hint}</span>
          </span>
          <span />
        </div>
      </div>
    </Card>
  );
}
