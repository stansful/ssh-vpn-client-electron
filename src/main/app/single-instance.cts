/** @type {(application: { requestSingleInstanceLock(additionalData?: Record<string, unknown>): boolean; exit(exitCode?: number): void }, additionalData?: Record<string, unknown>) => boolean} */
// @ts-expect-error -- the CommonJS bootstrap loader requires this dependency to remain syntax-valid plain JavaScript.
export const acquireSingleInstanceLock = (application, additionalData = {}) => {
  const acquired = application.requestSingleInstanceLock(additionalData);
  if (!acquired) {
    // A secondary process has no state to flush. Exiting synchronously also
    // prevents bootstrap from importing the main module and creating a window.
    application.exit(0);
  }
  return acquired;
};
