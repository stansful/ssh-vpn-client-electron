import { ArrowRight, Check, Download, ExternalLink, Folder, Info, Package, RefreshCw, TriangleAlert } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { GITHUB_REPOSITORY_URL } from "../../../../shared/links.js";
import { Button, Callout, Card, CardHeader, cx, Icon, LinkButton, Progress, Spinner } from "../../ui/index.js";
import { platformCopy, presentUpdates, sectionElementId, type UpdatesPresentation } from "./settings-model.js";

const BADGE_DOT: Record<UpdatesPresentation["badge"]["tone"], string | undefined> = {
  accent: "st-dot-accent",
  ok: "t-ok",
  danger: "t-danger",
  outline: undefined,
  busy: undefined
};

/**
 * Updates: checked only on request, downloaded in the background (never
 * blocks Connect), installed by the person. Windows only; elsewhere it points
 * to GitHub.
 */
export function UpdatesSection(): JSX.Element {
  const { snapshot, environment, run, toast, navigate } = useAppData();
  const copy = platformCopy(environment.platform);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<unknown>();
  const [downloadError, setDownloadError] = useState<unknown>();
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const view = presentUpdates({
    platform: environment.platform,
    arch: environment.arch,
    currentVersion: environment.version,
    info: snapshot.updateInfo,
    download: snapshot.updateDownload,
    checking,
    checkError,
    downloadError
  });

  // "Update downloaded" is announced app-wide (useSystemToasts), on any page.

  const check = async (): Promise<void> => {
    if (checking) {
      return;
    }
    setChecking(true);
    setCheckError(undefined);
    setDownloadError(undefined);
    try {
      await run(() => api.checkForUpdates(true), { background: true, silent: true, rethrow: true });
    } catch (error) {
      if (mounted.current) {
        setCheckError(error);
      }
    } finally {
      if (mounted.current) {
        setChecking(false);
      }
    }
  };

  const download = async (): Promise<void> => {
    setDownloadError(undefined);
    try {
      await run(() => api.downloadUpdate(), { background: true, silent: true, rethrow: true });
    } catch (error) {
      // On this page the failure shows inline; elsewhere it needs a toast to be seen at all.
      if (mounted.current) {
        setDownloadError(error);
      } else {
        toast({
          id: "update-download-failed",
          tone: "error",
          title: "Couldn't download the update",
          message: "Open Settings → Updates to try again.",
          action: { label: "Open Updates", onClick: () => navigate("settings", { type: "settings-section", section: "updates" }) }
        });
      }
    }
  };

  const reveal = async (): Promise<void> => {
    const revealed = await run(() => api.revealDownloadedUpdate(), { errorTitle: "Couldn't open the updates folder" });
    if (revealed === true) {
      toast({ tone: "info", title: "Opened the updates folder", message: `${copy.fileManager} shows the downloaded file.` });
    } else if (revealed === false) {
      toast({ tone: "error", title: "Couldn't find the downloaded file", message: "It may have been moved or deleted. Download the update again." });
    }
  };

  const openGitHub = (): void => {
    // The exact release when the check found one; the main process allows this repository's release pages.
    const url = snapshot.updateInfo?.available && snapshot.updateInfo.releaseUrl ? snapshot.updateInfo.releaseUrl : GITHUB_REPOSITORY_URL;
    void run(() => api.openExternal(url), { errorTitle: "Couldn't open GitHub" });
  };

  const supported = view.phase !== "unsupported";
  const busyBadge = view.badge.tone === "busy";
  const { download: dl } = view;
  const offered = view.fileLine !== undefined;

  return (
    <Card id={sectionElementId("updates")} className="st-section" rise={6} aria-labelledby="st-updates-h" tabIndex={-1}>
      <CardHeader
        level={2}
        titleId="st-updates-h"
        icon={Package}
        title="Updates"
        sub="Shadow SSH checks GitHub only when you ask and never installs anything on its own."
        tools={
          <span className={cx("badge", view.badge.tone === "outline" ? "t-outline" : `t-${view.badge.tone}`)}>
            {busyBadge ? <Spinner size="md" /> : view.badge.dot ? <span className={cx("dot", BADGE_DOT[view.badge.tone])} aria-hidden="true" /> : null}
            {view.badge.text}
          </span>
        }
      />

      <div className="st-upd" aria-live="polite">
        <div className="st-ver">
          <div className="st-ver-col">
            <span className="eyebrow">Installed</span>
            <span className="st-ver-num">{environment.version}</span>
          </div>
          {view.latestVersion ? (
            <>
              <Icon icon={ArrowRight} className="faint" />
              <div className="st-ver-col rise">
                <span className="eyebrow">Available</span>
                <span className="st-ver-num st-ver-new">{view.latestVersion}</span>
              </div>
            </>
          ) : null}
        </div>

        {supported ? (
          <div className="st-status anim-swap" key={view.phase}>
            <span className={cx("st-status-title", view.titleDanger && "st-bad")}>
              {checking ? <Spinner className="st-status-spin" /> : null}
              {view.title}
            </span>
            {view.sub ? <span className="muted st-status-sub">{view.sub}</span> : null}
            {view.fileLine ? <span className="st-file">{view.fileLine}</span> : null}
          </div>
        ) : (
          <div className="st-compact">
            <Icon icon={Info} size="sm" />
            <span>In-app updates are available on Windows. Download new versions from GitHub.</span>
            <LinkButton icon={ExternalLink} onClick={openGitHub}>
              Open GitHub
            </LinkButton>
          </div>
        )}
      </div>

      {offered && dl.state === "downloading" ? (
        <div className="st-dl rise">
          <div className="st-dl-top">
            <span className="st-pct">{dl.percent}%</span>
            <span className="muted">Downloading {view.latestVersion}</span>
            <span className="spacer" />
            <span className="mono faint st-dl-bytes">{dl.bytesText}</span>
          </div>
          <Progress value={dl.percent} label="Update download" />
          <span className="hint">Connect and Disconnect stay available while this downloads.</span>
        </div>
      ) : null}

      {offered && dl.state === "downloaded" ? (
        <Callout tone="ok" icon={Check} title={`Downloaded · ${view.latestVersion} is ready to run`} className="rise">
          Shadow SSH doesn’t install updates itself. Quit it from the {copy.trayWord}, then run the downloaded file. Your servers, keys and settings stay as they
          are.
          {dl.filePath ? <span className="st-file st-callout-file">{dl.filePath}</span> : null}
        </Callout>
      ) : null}

      {offered && dl.state === "failed" && dl.failure ? (
        <Callout tone="danger" icon={TriangleAlert} title="Download failed" className="rise">
          {dl.failure.message}
        </Callout>
      ) : null}

      {supported ? (
        <div className="row-wrap">
          {view.canDownload ? (
            <Button variant="primary" icon={Download} onClick={() => void download()}>
              {view.downloadLabel}
            </Button>
          ) : null}
          {offered && dl.state === "downloading" ? (
            <Button variant="primary" busy>
              Downloading…
            </Button>
          ) : null}
          {offered && dl.state === "downloaded" ? (
            <Button variant="primary" icon={Folder} onClick={() => void reveal()}>
              Show in folder
            </Button>
          ) : null}
          <Button icon={RefreshCw} busy={checking} disabled={view.check.disabled} title={view.check.title} onClick={() => void check()}>
            {view.check.label}
          </Button>
        </div>
      ) : null}
    </Card>
  );
}
