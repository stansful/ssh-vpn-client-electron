import { RotateCcw } from "lucide-react";
import { useCallback, useEffect, useMemo } from "react";
import { api } from "./api.js";
import { ActivityPage } from "./components/pages/activity/ActivityPage.js";
import { ConnectPage } from "./components/pages/connect/ConnectPage.js";
import { KeysPage } from "./components/pages/keys/KeysPage.js";
import { ProfilesPage } from "./components/pages/profiles/ProfilesPage.js";
import { RoutingPage } from "./components/pages/routing/RoutingPage.js";
import { ServersPage } from "./components/pages/servers/ServersPage.js";
import { SettingsPage } from "./components/pages/settings/SettingsPage.js";
import { AppShell, DataRecoveryScreen, StartupScreen } from "./components/shell/index.js";
import { ConfirmHost, copyTextWithFeedback, ToastViewport } from "./components/ui/index.js";
import { AppDataContext, type AppData } from "./hooks/useAppData.js";
import { useAsyncAction } from "./hooks/useAsyncAction.js";
import { ConfirmContext, useConfirmController } from "./hooks/useConfirm.js";
import { NavigationContext, useNavigationState } from "./hooks/useNavigation.js";
import { useApplyTheme } from "./hooks/useResolvedTheme.js";
import { useSnapshot } from "./hooks/useSnapshot.js";
import { useSystemToasts } from "./hooks/useSystemToasts.js";
import { ToastContext, useToastController } from "./hooks/useToasts.js";
import { describeError } from "./lib/errors.js";
import type { PageProps, View } from "./types.js";
import type { AppSettings } from "../shared/types.js";

const PAGES: Record<View, (props: PageProps) => JSX.Element> = {
  connect: ConnectPage,
  routing: RoutingPage,
  servers: ServersPage,
  profiles: ProfilesPage,
  keys: KeysPage,
  activity: ActivityPage,
  settings: SettingsPage
};

export function App(): JSX.Element {
  const { toasts, api: toastApi } = useToastController();
  const confirmController = useConfirmController();
  const navigation = useNavigationState("connect");
  const { navigate } = navigation;

  const { snapshot, setSnapshot, startup, reload } = useSnapshot({
    onServiceError: (message) => {
      const described = describeError(message);
      toastApi.toast({ tone: "error", title: "The connection service reported an error", message: described.message, details: described.technical });
    },
    onRefreshError: (error, retry) => {
      const described = describeError(error);
      toastApi.toast({
        id: "snapshot-refresh-failed",
        tone: "error",
        title: "Couldn't refresh the window",
        message: "The background service didn't answer, so what you see may be out of date.",
        details: described.technical ?? described.message,
        action: { label: "Try again", icon: RotateCcw, onClick: retry }
      });
    }
  });

  useApplyTheme(snapshot?.store.settings);
  const { busy, run } = useAsyncAction({ setSnapshot, toast: toastApi.toast });
  useSystemToasts(snapshot, toastApi, navigate);

  const loggingEnabled = snapshot?.store.settings.loggingEnabled ?? true;
  useEffect(() => {
    if (!loggingEnabled && navigation.view === "activity") {
      navigate("connect");
    }
  }, [loggingEnabled, navigate, navigation.view]);

  const updateSettings = useCallback(
    (patch: Partial<AppSettings>) => run(() => api.updateSettings(patch), { background: true, errorTitle: "Couldn't save the setting" }),
    [run]
  );
  const copyText = useCallback((text: string) => copyTextWithFeedback(text, toastApi.toast), [toastApi.toast]);

  const appData = useMemo<AppData | null>(() => {
    if (!snapshot) {
      return null;
    }
    return {
      snapshot,
      store: snapshot.store,
      runtime: snapshot.runtime,
      activeTransport: snapshot.activeTransport,
      environment: snapshot.environment,
      busy,
      run,
      toast: toastApi.toast,
      dismissToast: toastApi.dismiss,
      confirm: confirmController.confirm,
      navigate,
      setSnapshot,
      updateSettings,
      copyText,
      reloadSnapshot: reload
    };
  }, [busy, confirmController.confirm, copyText, navigate, reload, run, setSnapshot, snapshot, toastApi.dismiss, toastApi.toast, updateSettings]);

  let content: JSX.Element;
  if (!snapshot || !appData) {
    content = <StartupScreen startup={startup} onRetry={reload} />;
  } else if (snapshot.storageHealth.state === "unreadable") {
    content = <DataRecoveryScreen health={snapshot.storageHealth} onRecovered={setSnapshot} />;
  } else {
    const Page = PAGES[navigation.view];
    content = (
      <AppShell>
        <Page intent={navigation.intent} />
      </AppShell>
    );
  }

  return (
    <ToastContext.Provider value={toastApi}>
      <ConfirmContext.Provider value={confirmController.confirm}>
        <NavigationContext.Provider value={navigation}>
          <AppDataContext.Provider value={appData}>
            <div
              className="app"
              data-startup-state={snapshot ? "ready" : startup.phase}
              data-connection-state={snapshot?.runtime.state ?? "Disconnected"}
              data-active-transport={snapshot?.activeTransport}
            >
              {content}
              <ToastViewport toasts={toasts} onDismiss={toastApi.dismiss} />
              <ConfirmHost controller={confirmController} />
            </div>
          </AppDataContext.Provider>
        </NavigationContext.Provider>
      </ConfirmContext.Provider>
    </ToastContext.Provider>
  );
}
