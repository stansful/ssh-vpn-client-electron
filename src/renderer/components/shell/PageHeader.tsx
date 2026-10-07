import { useEffect, useRef, type ReactNode } from "react";
import { useNavigation } from "../../hooks/useNavigation.js";
import { cx } from "../ui/Icon.js";

export interface PageHeaderProps {
  /** Group name above the title: "Tunnel", "Library", "App". */
  eyebrow?: string;
  /** Page title (Unbounded); receives focus after navigating here. */
  title: string;
  /** One sentence about the page. */
  sub?: ReactNode;
  /** Right side: the page's one primary action, segmented controls, tools. */
  actions?: ReactNode;
  className?: string;
}

/**
 * Page header (`.topbar`). After a navigation the title takes focus so screen
 * readers announce the new page; the first page after startup does not steal focus.
 */
export function PageHeader({ eyebrow, title, sub, actions, className }: PageHeaderProps): JSX.Element {
  const titleRef = useRef<HTMLHeadingElement>(null);
  const { navigationId } = useNavigation();
  const mountedNavigationId = useRef(navigationId);

  useEffect(() => {
    if (mountedNavigationId.current === 0) {
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => {
      if (!document.querySelector(".overlay")) {
        titleRef.current?.focus({ preventScroll: true });
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  return (
    <header className={cx("topbar rise", className)}>
      <div className="topbar-copy">
        {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
        <h1 className="page-title" ref={titleRef} tabIndex={-1}>
          {title}
        </h1>
        {sub ? <p className="page-sub">{sub}</p> : null}
      </div>
      {actions ? <div className="topbar-actions">{actions}</div> : null}
    </header>
  );
}
