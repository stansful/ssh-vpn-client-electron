import { useEffect, useRef, useState } from "react";

/** A deleted item kept on screen while it plays its exit animation. */
export interface ExitingItem<T> {
  id: string;
  item: T;
  /** Position it had in the list, so it leaves from where it was. */
  index: number;
}

export interface ListEntry<T> {
  item: T;
  leaving: boolean;
}

/** Puts leaving items back at their old positions among the current ones. */
export function mergeExiting<T>(items: readonly T[], exiting: ReadonlyArray<ExitingItem<T>>, getId: (item: T) => string): Array<ListEntry<T>> {
  const entries: Array<ListEntry<T>> = items.map((item) => ({ item, leaving: false }));
  const present = new Set(items.map(getId));
  const ordered = exiting.filter((ghost) => !present.has(ghost.id)).sort((a, b) => a.index - b.index);
  for (const ghost of ordered) {
    entries.splice(Math.min(ghost.index, entries.length), 0, { item: ghost.item, leaving: true });
  }
  return entries;
}

/** Items marked as leaving that disappeared between two versions of the list. */
export function findExiting<T>(
  previous: readonly T[],
  next: readonly T[],
  marked: ReadonlySet<string>,
  getId: (item: T) => string
): Array<ExitingItem<T>> {
  if (marked.size === 0) {
    return [];
  }
  const nextIds = new Set(next.map(getId));
  return previous.flatMap((item, index) => {
    const id = getId(item);
    return marked.has(id) && !nextIds.has(id) ? [{ id, item, index }] : [];
  });
}

/**
 * Keeps items deleted from this page on screen with `leaving: true` for
 * `durationMs`, so their row can collapse instead of vanishing. Only ids
 * passed to `markLeaving` animate; anything else (search, other windows)
 * updates instantly. The ghost is added in the same render that drops the
 * item, so the element stays mounted and its CSS transition runs.
 */
export function useExitingItems<T>(
  items: readonly T[],
  getId: (item: T) => string,
  durationMs: number
): { entries: Array<ListEntry<T>>; markLeaving: (id: string) => void } {
  const marked = useRef(new Set<string>());
  const [state, setState] = useState<{ source: readonly T[]; exiting: Array<ExitingItem<T>> }>({ source: items, exiting: [] });

  // Derived during render (pure, so StrictMode's double render agrees).
  let current = state;
  if (state.source !== items) {
    const gone = findExiting(state.source, items, marked.current, getId).filter(
      (ghost) => !state.exiting.some((existing) => existing.id === ghost.id)
    );
    current = { source: items, exiting: [...state.exiting, ...gone] };
    setState(current);
  }

  const exitingIds = current.exiting.map((ghost) => ghost.id).join("|");
  useEffect(() => {
    if (!exitingIds) {
      return undefined;
    }
    const ids = new Set(exitingIds.split("|"));
    const timer = window.setTimeout(() => {
      for (const id of ids) {
        marked.current.delete(id);
      }
      setState((latest) => ({ ...latest, exiting: latest.exiting.filter((ghost) => !ids.has(ghost.id)) }));
    }, durationMs);
    return () => window.clearTimeout(timer);
  }, [durationMs, exitingIds]);

  const markLeaving = useRef((id: string): void => {
    marked.current.add(id);
  }).current;

  return { entries: mergeExiting(items, current.exiting, getId), markLeaving };
}
