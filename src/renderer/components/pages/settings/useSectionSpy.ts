import { useCallback, useEffect, useRef, useState, type RefObject } from "react";
import type { SettingsSection } from "../../../types.js";
import { activeSectionAt, SETTINGS_SECTIONS, sectionElementId } from "./settings-model.js";

/** A section is "current" once its top passes this share of the scroll area (at least the minimum below). */
const SPY_OFFSET_SHARE = 0.3;
const SPY_OFFSET_MIN_PX = 96;
/** Fallback for engines without `scrollend`: release the click lock after this. */
const SCROLL_LOCK_MS = 900;
const SCROLL_SETTLE_MS = 150;

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Local section navigation: tracks which card is in view while the main
 * column scrolls, and scrolls to a card on request. While a requested scroll
 * runs, the highlight stays on the requested card instead of sliding through
 * every card it passes.
 */
export function useSectionSpy(containerRef: RefObject<HTMLElement>): {
  current: SettingsSection;
  goTo: (section: SettingsSection, options?: { focus?: boolean; instant?: boolean }) => void;
} {
  const [current, setCurrent] = useState<SettingsSection>("general");
  const locked = useRef<SettingsSection>();
  const lockTimer = useRef<number>();

  const measure = useCallback((): void => {
    const scroller = containerRef.current?.closest<HTMLElement>(".main");
    if (!scroller || locked.current) {
      return;
    }
    const rootTop = scroller.getBoundingClientRect().top;
    const sections = SETTINGS_SECTIONS.flatMap((id) => {
      const element = document.getElementById(sectionElementId(id));
      return element ? [{ id, top: element.getBoundingClientRect().top - rootTop }] : [];
    });
    const atBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 4 && scroller.scrollTop > 0;
    const threshold = Math.max(SPY_OFFSET_MIN_PX, scroller.clientHeight * SPY_OFFSET_SHARE);
    const next = activeSectionAt(sections, threshold, atBottom);
    if (next) {
      setCurrent(next);
    }
  }, [containerRef]);

  useEffect(() => {
    const scroller = containerRef.current?.closest<HTMLElement>(".main");
    if (!scroller) {
      return undefined;
    }
    let frame: number | undefined;
    const onScroll = (): void => {
      if (frame === undefined) {
        frame = window.requestAnimationFrame(() => {
          frame = undefined;
          measure();
        });
      }
    };
    const release = (): void => {
      if (locked.current) {
        locked.current = undefined;
        window.clearTimeout(lockTimer.current);
      }
    };
    // The last scroll frames of a requested jump may still be queued when it ends.
    const releaseSoon = (): void => {
      if (locked.current) {
        window.clearTimeout(lockTimer.current);
        lockTimer.current = window.setTimeout(release, SCROLL_SETTLE_MS);
      }
    };
    // Wheel or touch input means the person took over the scroll.
    scroller.addEventListener("scroll", onScroll, { passive: true });
    scroller.addEventListener("scrollend", releaseSoon);
    scroller.addEventListener("wheel", release, { passive: true });
    scroller.addEventListener("touchstart", release, { passive: true });
    return () => {
      scroller.removeEventListener("scroll", onScroll);
      scroller.removeEventListener("scrollend", releaseSoon);
      scroller.removeEventListener("wheel", release);
      scroller.removeEventListener("touchstart", release);
      if (frame !== undefined) {
        window.cancelAnimationFrame(frame);
      }
      window.clearTimeout(lockTimer.current);
    };
  }, [containerRef, measure]);

  const goTo = useCallback((section: SettingsSection, options: { focus?: boolean; instant?: boolean } = {}): void => {
    const element = document.getElementById(sectionElementId(section));
    if (!element) {
      return;
    }
    setCurrent(section);
    locked.current = section;
    window.clearTimeout(lockTimer.current);
    lockTimer.current = window.setTimeout(() => {
      locked.current = undefined;
    }, SCROLL_LOCK_MS);
    element.scrollIntoView({ behavior: options.instant || prefersReducedMotion() ? "auto" : "smooth", block: "start" });
    if (options.focus) {
      element.focus({ preventScroll: true });
    }
  }, []);

  return { current, goTo };
}
