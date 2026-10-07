import { Download, ExternalLink, Globe } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../../api.js";
import { useAppData } from "../../../hooks/useAppData.js";
import { formatCount, formatWhen } from "../../../lib/format.js";
import { ROUTING_DOMAIN_LIST_SOURCE_URL } from "../../../../shared/links.js";
import { Button, Callout, EmptyState, LinkButton, Modal, SearchInput } from "../../ui/index.js";
import { describeListError, filterDomains, LIST_SOURCE_LABEL, listName, type DomainList, type DomainRow, type ListKind } from "./routing-model.js";
import type { RoutingController } from "./useRoutingController.js";

const ROW_HEIGHT = 35;
const VIEWPORT_HEIGHT = 286;
const OVERSCAN = 6;

/** Read-only view of a downloaded list, with search. Viewing never changes the list. */
export function DomainListViewer({ ctl, kind, open }: { ctl: RoutingController; kind: ListKind; open: boolean }): JSX.Element {
  const { run } = useAppData();
  const list: DomainList = kind === "proxy" ? ctl.proxyList : ctl.directList;
  const [query, setQuery] = useState("");
  const name = listName(kind);
  const count = list.domains.length;
  const rows = useMemo(() => filterDomains(list.domains, query), [list.domains, query]);
  const trimmed = query.trim().toLowerCase();
  const busy = ctl.listBusy[kind];
  const error = ctl.listErrors[kind];
  const proxy = kind === "proxy";

  useEffect(() => {
    if (!open) {
      setQuery("");
    }
  }, [open]);

  const where = proxy ? "sent through the tunnel" : "kept direct";
  const description = count > 0
    ? `${formatCount(count)} domains, ${list.enabled ? where : `${where} once the list is on`}.${list.updatedAt ? ` Refreshed ${formatWhen(list.updatedAt)}.` : ""}`
    : `${proxy ? "Sent through the tunnel" : "Kept direct"} once it is downloaded and turned on.`;
  const countLine = trimmed
    ? `${rows.length === 1 ? "1 match" : `${formatCount(rows.length)} matches`} for “${trimmed}”`
    : `${formatCount(count)} domains · A to Z`;
  const errorCopy = error ? describeListError(error, kind, list) : undefined;

  return (
    <Modal
      open={open}
      onClose={ctl.closeDialog}
      eyebrow="Routing · domain list"
      icon={Globe}
      iconTone={proxy ? "ok" : "info"}
      title={name}
      description={description}
      footer={
        <>
          <LinkButton
            icon={ExternalLink}
            className="lead rt-foot-source"
            aria-label="Open list source itdoginfo/allow-domains on GitHub"
            onClick={() => void run(() => api.openExternal(ROUTING_DOMAIN_LIST_SOURCE_URL), { errorTitle: "Couldn’t open GitHub" })}
          >
            {LIST_SOURCE_LABEL}
          </LinkButton>
          <Button onClick={ctl.closeDialog}>Close</Button>
        </>
      }
    >
      {count > 0 ? (
        <div className="stack">
          <SearchInput
            value={query}
            onValueChange={setQuery}
            placeholder={`Search ${formatCount(count)} domains`}
            aria-label="Search domains"
            autoComplete="off"
          />
          <div className="rt-row-between">
            <span className="hint" aria-live="polite">
              {countLine}
            </span>
            <span className="hint">A leading dot covers the whole zone</span>
          </div>
          <VirtualDomainList rows={rows} label={`${name} domains`} query={trimmed} />
        </div>
      ) : (
        <EmptyState
          icon={Download}
          title="Not downloaded yet"
          className="anim-swap"
          action={
            <Button variant="primary" busy={busy === "downloading"} busyLabel="Downloading…" disabled={Boolean(busy)} onClick={() => ctl.refreshList(kind)}>
              Download now
            </Button>
          }
        >
          This list comes from GitHub the first time you turn it on or refresh it. The download can take up to 15 s, and fails if GitHub is
          blocked on your network.
        </EmptyState>
      )}
      {errorCopy ? (
        <Callout tone="danger" role="alert" title={errorCopy.title}>
          {errorCopy.text}
        </Callout>
      ) : null}
    </Modal>
  );
}

/** Only the rows in view are rendered, so a 20,000-domain list scrolls and filters smoothly. */
function VirtualDomainList({ rows, label, query }: { rows: DomainRow[]; label: string; query: string }): JSX.Element {
  const scroller = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);

  useEffect(() => {
    scroller.current?.scrollTo({ top: 0 });
    setScrollTop(0);
  }, [rows]);

  if (rows.length === 0) {
    return (
      <div className="rt-domains">
        <div className="rt-nomatch">No domains match “{query}”. Try part of a name, like discord or google.</div>
      </div>
    );
  }

  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const end = Math.min(rows.length, Math.ceil((scrollTop + VIEWPORT_HEIGHT) / ROW_HEIGHT) + OVERSCAN);
  return (
    <div
      ref={scroller}
      className="rt-domains"
      role="list"
      aria-label={label}
      tabIndex={0}
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    >
      <div className="rt-domains-track" style={{ height: rows.length * ROW_HEIGHT }}>
        {rows.slice(start, end).map((row, offset) => {
          const index = start + offset;
          return (
            <div
              key={row.domain}
              className="rt-domain"
              role="listitem"
              aria-setsize={rows.length}
              aria-posinset={index + 1}
              data-first={index === 0}
              style={{ top: index * ROW_HEIGHT }}
            >
              <span className="rt-domain-name">
                {row.pre}
                {row.hit ? <mark>{row.hit}</mark> : null}
                {row.post}
              </span>
              {row.zone ? <span className="rt-zone">whole zone</span> : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
