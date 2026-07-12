export interface SingleInstanceApplication {
  requestSingleInstanceLock(additionalData?: Record<string, unknown>): boolean;
  quit(): void;
}

export function acquireSingleInstanceLock(
  application: SingleInstanceApplication,
  additionalData: Record<string, unknown> = {}
): boolean {
  const acquired = application.requestSingleInstanceLock(additionalData);
  if (!acquired) {
    application.quit();
  }
  return acquired;
}

/**
 * Electron terminates a secondary process after app.quit(). Keeping module
 * evaluation pending prevents any primary-instance initialization meanwhile.
 */
export function waitForSecondaryInstanceExit(): Promise<never> {
  return new Promise<never>(() => undefined);
}
