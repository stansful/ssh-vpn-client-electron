import { ArrowRight, Copy, ExternalLink, Eye, Github, Globe, RefreshCw, ShieldCheck } from "lucide-react";
import type { CSSProperties } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { ROUTING_DOMAIN_LIST_SOURCE_URL } from "../../../../shared/links.js";
import { Badge, Button, Callout, Card, CardHeader, cx, Icon, IconButton, Progress, Spinner, Switch, useCopyFeedback } from "../../ui/index.js";
import { describeListError, LIST_SOURCE_LABEL, listMetaText, listName, type DomainList, type ListKind } from "./routing-model.js";
import { listsInUseText, type RoutingController } from "./useRoutingController.js";

const LIST_COPY: Record<ListKind, { desc: string; direction: string }> = {
  proxy: { desc: "Sites blocked or throttled in Russia, like YouTube and Instagram.", direction: "Through tunnel" },
  direct: { desc: "Russian sites that work best without a tunnel, like banks and government services.", direction: "Stays direct" }
};

/** The two community lists (Blocked in Russia → tunnel, Russian services → direct) and where they come from. */
export function DomainListsCard({ ctl }: { ctl: RoutingController }): JSX.Element {
  const inUse = listsInUseText(ctl.proxyList, ctl.directList);
  return (
    <Card rise={2} aria-labelledby="rt-lists-title">
      <CardHeader
        level={2}
        titleId="rt-lists-title"
        icon={Globe}
        title="Domain lists"
        sub="Community lists that cover hundreds of sites at once. Turn one on instead of adding sites by hand."
        tools={<Badge tone={inUse ? "accent" : "outline"}>{inUse ?? "None in use"}</Badge>}
      />
      <div className="rt-lists">
        <ListRow ctl={ctl} kind="proxy" list={ctl.proxyList} index={1} />
        <ListRow ctl={ctl} kind="direct" list={ctl.directList} index={2} />
      </div>
      <SourceRow />
    </Card>
  );
}

function ListRow({ ctl, kind, list, index }: { ctl: RoutingController; kind: ListKind; list: DomainList; index: number }): JSX.Element {
  const name = listName(kind);
  const busy = ctl.listBusy[kind];
  const error = ctl.listErrors[kind];
  const hasData = list.domains.length > 0;
  const switching = busy === "turning-on" || busy === "turning-off" || busy === "downloading";
  const downloading = busy === "downloading" || busy === "refreshing";
  const meta = listMetaText(list, busy);
  const errorCopy = error ? describeListError(error, kind, list) : undefined;
  const proxy = kind === "proxy";

  return (
    <div className="rt-list rise" data-on={list.enabled} aria-busy={busy ? true : undefined} style={{ "--d": index } as CSSProperties}>
      <span className={cx("icon-tile rt-list-ic", list.enabled && (proxy ? "t-busy" : "t-info"))} aria-hidden="true">
        <Icon icon={proxy ? ShieldCheck : ArrowRight} />
      </span>

      <div className="rt-list-main">
        <div className="rt-list-title">
          <span>{name}</span>
          <Badge square tone={proxy ? "accent" : "outline"}>
            {LIST_COPY[kind].direction}
          </Badge>
          {proxy && ctl.mode === "proxy-all" && list.enabled ? (
            <Badge square tone="outline">
              Not needed in Full tunnel
            </Badge>
          ) : null}
        </div>
        <span className="rt-list-desc">{LIST_COPY[kind].desc}</span>
        <span className="rt-list-meta anim-swap" key={`${kind}-${busy ?? "idle"}-${list.domains.length}-${list.updatedAt ?? ""}`}>
          {meta}
        </span>
      </div>

      <div className="rt-list-tools">
        {hasData ? (
          <Button variant="ghost" size="sm" icon={Eye} aria-label={`View ${name} domains`} onClick={() => ctl.openViewer(kind)}>
            View
          </Button>
        ) : null}
        <Button
          size="sm"
          icon={RefreshCw}
          busy={busy === "refreshing"}
          busyLabel="Refreshing…"
          disabled={Boolean(busy)}
          aria-label={`Refresh ${name} list`}
          onClick={() => ctl.refreshList(kind)}
        >
          Refresh
        </Button>
      </div>

      <div className="rt-list-sw">
        <span className="rt-sw-state" aria-hidden="true">
          {switching ? <Spinner /> : list.enabled ? "On" : "Off"}
        </span>
        <Switch checked={list.enabled} disabled={Boolean(busy)} aria-label={`Use ${name} list`} onCheckedChange={() => ctl.toggleList(kind)} />
      </div>

      {errorCopy ? (
        <Callout
          tone="danger"
          role="alert"
          className="rt-list-err anim-swap"
          title={errorCopy.title}
          actions={
            <Button size="sm" aria-label={`Try downloading ${name} again`} disabled={Boolean(busy)} onClick={() => ctl.retryList(kind)}>
              Try again
            </Button>
          }
        >
          {errorCopy.text}
        </Callout>
      ) : null}

      {downloading ? <Progress label={`Downloading ${name}`} className="rt-list-bar" /> : null}
    </div>
  );
}

function SourceRow(): JSX.Element {
  const { run, toast } = useAppData();
  const { copied, copy } = useCopyFeedback();
  return (
    <div className="rt-source">
      <span className="rt-source-ic" aria-hidden="true">
        <Icon icon={Github} />
      </span>
      <div className="rt-source-copy">
        <span>
          Source: <span className="mono">{LIST_SOURCE_LABEL}</span>
        </span>
        <span className="hint">Lists download directly from GitHub, not through the tunnel.</span>
      </div>
      <div className="rt-source-tools">
        <IconButton
          icon={ExternalLink}
          label="Open list source on GitHub"
          tooltip="Open on GitHub"
          onClick={() => void run(() => api.openExternal(ROUTING_DOMAIN_LIST_SOURCE_URL), { errorTitle: "Couldn’t open GitHub" })}
        />
        <IconButton
          icon={Copy}
          label="Copy list source link"
          tooltip={copied ? "Copied" : "Copy link"}
          done={copied}
          onClick={() => {
            void copy(ROUTING_DOMAIN_LIST_SOURCE_URL).then((ok) => {
              if (ok) {
                toast({ tone: "success", title: "Source link copied", message: "github.com/itdoginfo/allow-domains" });
              }
            });
          }}
        />
      </div>
    </div>
  );
}
