import { useAppData } from "../../../hooks/useAppData.js";
import type { GlobalTab } from "../../../../shared/types.js";
import { redirectsSystemTraffic } from "../../../lib/connection.js";
import { formatTransportSecurity } from "../../../lib/format.js";
import { formatLocalProxy, runtimeLocalProxy } from "../../../lib/runtime-message.js";
import { Badge, Callout, CopyButton, Fact, LinkButton } from "../../ui/index.js";
import type { ConnectTarget } from "./connect-target.js";

/**
 * Facts under a connected hero: where the local proxy listens (with Copy),
 * which protocols it speaks, and the host key (SSH) or transport (Xray). On
 * macOS and Linux nothing is redirected, so it also says where to point apps.
 */
export function HeroFacts({ transport, target }: { transport: GlobalTab; target?: ConnectTarget }): JSX.Element {
  const { runtime, environment, navigate } = useAppData();
  const proxy = runtimeLocalProxy(runtime);
  const address = proxy ? formatLocalProxy(proxy) : undefined;
  const socks = proxy?.socksPort ? formatLocalProxy({ host: proxy.host, httpPort: proxy.socksPort }) : undefined;
  const ssh = transport === "ssh";
  const config = target?.config;
  const pinned = Boolean(config?.expectedServerFingerprint.trim());

  return (
    <div className="stack hero-facts">
      <div className="facts cn-facts">
        <Fact label="Local proxy">
          {address ? (
            <>
              <span className="mono truncate">{address}</span>
              <CopyButton text={address} label="Copy local proxy address" className="cn-fact-copy" />
            </>
          ) : (
            <span className="faint">Not reported yet</span>
          )}
        </Fact>
        <Fact label="Protocols">
          {socks ? (
            <span className="truncate">
              HTTP · SOCKS5 <span className="mono faint">{socks}</span>
            </span>
          ) : (
            "HTTP · SOCKS5"
          )}
        </Fact>
        {ssh ? (
          <Fact label="Host key">
            {pinned ? (
              <Badge tone="ok" square>
                Pinned · verified
              </Badge>
            ) : config ? (
              <>
                <Badge tone="warn" square title={runtime.observedHostKeyFingerprint}>
                  Not pinned
                </Badge>
                <LinkButton icon={null} onClick={() => navigate("servers", { type: "edit-server", id: config.id })}>
                  Pin it
                </LinkButton>
              </>
            ) : (
              <Badge tone="outline" square>
                Unknown
              </Badge>
            )}
          </Fact>
        ) : (
          <Fact label="Transport">
            {target?.profile ? (
              <Badge tone="ok" square>
                {formatTransportSecurity(target.profile)}
              </Badge>
            ) : (
              <span className="faint">Unknown</span>
            )}
          </Fact>
        )}
      </div>
      {!redirectsSystemTraffic(environment.platform) && address ? (
        <Callout
          tone="info"
          title={
            <>
              Point your apps at <span className="mono">{address}</span>
            </>
          }
        >
          {socks
            ? `Set it as the HTTP proxy, or ${socks} as the SOCKS5 proxy, in each app you want to tunnel.`
            : "Set it as the HTTP or SOCKS5 proxy in each app you want to tunnel."}{" "}
          Routing rules and domain lists don’t filter traffic on macOS or Linux.
        </Callout>
      ) : null}
    </div>
  );
}
