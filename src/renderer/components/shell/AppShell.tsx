import { useLayoutEffect, useRef, type ReactNode } from "react";
import { useNavigation } from "../../hooks/useNavigation.js";
import { PreviewBanner } from "./PreviewBanner.js";
import { Sidebar } from "./Sidebar.js";

/**
 * Sidebar + main column. The page view remounts per view so its entrance
 * choreography replays; the main column scrolls back to the top on every
 * navigation. Lives inside the `.app` container (see App).
 */
export function AppShell({ children }: { children: ReactNode }): JSX.Element {
  const { view, navigationId } = useNavigation();
  const mainRef = useRef<HTMLElement>(null);

  useLayoutEffect(() => {
    // Instant: a smooth scroll (the main column has scroll-behavior: smooth)
    // would animate over the new page and can be cut short by its layout.
    mainRef.current?.scrollTo({ top: 0, behavior: "instant" });
  }, [navigationId]);

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main" ref={mainRef} id="main" tabIndex={-1} data-view={view}>
        <div className="page">
          <PreviewBanner />
          <div className="page-view" key={view}>
            {children}
          </div>
        </div>
      </main>
    </div>
  );
}
