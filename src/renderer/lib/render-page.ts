export function sliceRenderPage<T>(items: readonly T[], visibleCount: number): T[] {
  return items.slice(0, Math.max(0, visibleCount));
}

export function nextRenderPageCount(current: number, total: number, pageSize: number): number {
  return Math.min(total, Math.max(0, current) + Math.max(1, pageSize));
}
