export function nextModalFocusIndex(
  currentIndex: number,
  itemCount: number,
  backwards: boolean
): number {
  const count = Number.isFinite(itemCount) ? Math.max(0, Math.floor(itemCount)) : 0;
  if (count === 0) {
    return -1;
  }
  if (!Number.isInteger(currentIndex) || currentIndex < 0 || currentIndex >= count) {
    return backwards ? count - 1 : 0;
  }
  if (backwards) {
    return currentIndex === 0 ? count - 1 : currentIndex - 1;
  }
  return currentIndex === count - 1 ? 0 : currentIndex + 1;
}

export class ModalFocusStack<T> {
  private readonly entries: T[] = [];

  activate(token: T): void {
    this.deactivate(token);
    this.entries.push(token);
  }

  deactivate(token: T): boolean {
    const wasTopmost = this.isTopmost(token);
    const index = this.entries.lastIndexOf(token);
    if (index >= 0) {
      this.entries.splice(index, 1);
    }
    return wasTopmost;
  }

  isTopmost(token: T): boolean {
    return this.entries.length > 0 && this.entries[this.entries.length - 1] === token;
  }
}
