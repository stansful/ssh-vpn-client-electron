import { Terminal, Zap } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import type { GlobalTab } from "../../../../shared/types.js";
import { PageHeader } from "../../shell/index.js";
import { Button, Callout, Segmented, type SegmentedOption } from "../../ui/index.js";
import { ConnectHero } from "./ConnectHero.js";
import { RecentActivityCard } from "./RecentActivityCard.js";
import { RoutingCard } from "./RoutingCard.js";
import { ServerTerminal } from "./ServerTerminal.js";
import { TunnelCheckCard } from "./TunnelCheckCard.js";

const TRANSPORT_OPTIONS: ReadonlyArray<SegmentedOption<GlobalTab>> = [
  { value: "ssh", label: "SSH", icon: Terminal },
  { value: "xray", label: "Xray", icon: Zap }
];

/**
 * Which transport Connect shows. Viewing a tab never connects or disconnects
 * anything; the choice is saved so it survives a restart. The main process
 * also flips it after a connect, so external changes are followed.
 */
function useTransportView(): [GlobalTab, (next: GlobalTab) => void] {
  const { store, updateSettings } = useAppData();
  const saved = store.settings.activeGlobalTab;
  const [view, setView] = useState<GlobalTab>(saved);
  const pending = useRef(0);

  useEffect(() => {
    if (pending.current === 0) {
      setView(saved);
    }
  }, [saved]);

  const choose = useCallback(
    (next: GlobalTab): void => {
      setView(next);
      pending.current += 1;
      void updateSettings({ activeGlobalTab: next }).finally(() => {
        pending.current -= 1;
      });
    },
    [updateSettings]
  );
  return [view, choose];
}

/** Connect: transport switch, the hero with the orb, routing / check / activity cards and the server terminal. */
export function ConnectPage(): JSX.Element {
  const { store, updateSettings } = useAppData();
  const [view, setView] = useTransportView();
  const [acceptingRisk, setAcceptingRisk] = useState(false);
  const showRisk = view === "xray" && !store.settings.xrayConsentAccepted;

  return (
    <>
      <PageHeader
        eyebrow="Tunnel"
        title="Connect"
        sub="Send your traffic through your own server — over SSH or an Xray profile."
        actions={<Segmented ariaLabel="Transport" value={view} options={TRANSPORT_OPTIONS} onChange={setView} />}
      />

      {showRisk ? (
        <Callout
          tone="warn"
          className="rise"
          title="Run only profiles you trust"
          actions={
            <Button
              size="sm"
              busy={acceptingRisk}
              onClick={() => {
                setAcceptingRisk(true);
                void updateSettings({ xrayConsentAccepted: true }).finally(() => setAcceptingRisk(false));
              }}
            >
              Got it
            </Button>
          }
        >
          VLESS, VMess, Trojan and Hysteria 2 profiles run in the bundled Xray engine, which carries your traffic. Import them only from sources you trust.
        </Callout>
      ) : null}

      <div className="split">
        <ConnectHero view={view} onShowTransport={setView} />
        <div className="stack">
          <RoutingCard />
          <TunnelCheckCard />
          {store.settings.loggingEnabled ? <RecentActivityCard /> : null}
        </div>
      </div>

      {view === "ssh" ? <ServerTerminal /> : null}
    </>
  );
}
