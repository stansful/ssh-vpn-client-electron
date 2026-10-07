export interface DescribedError {
  /** Short sentence-case title, e.g. "Couldn't check for updates". */
  title: string;
  /** What went wrong and what to do, in plain words. */
  message: string;
  /** The raw text for Technical details, when it differs from `message`. */
  technical?: string;
}

export interface DescribeErrorContext {
  /** Title to use instead of the generic one ("Couldn't save server"). */
  title?: string;
  /** What was being reached, for network errors ("GitHub", "the server"). */
  target?: string;
}

const DEFAULT_TITLE = "Something went wrong";
const REMOTE_METHOD_PREFIX = /^Error invoking remote method '[^']*':\s*(?:[A-Za-z]*Error:\s*)?/u;
const LEADING_ERROR_NAME = /^(?:Uncaught\s+)?(?:[A-Z][A-Za-z]*)?Error:\s+/u;

/** Raw text of anything thrown, including non-Error values. */
export function errorText(error: unknown): string {
  if (error instanceof Error) {
    return error.message || error.name;
  }
  if (typeof error === "string") {
    return error;
  }
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

/**
 * Removes the IPC envelope Electron puts around errors thrown in the main
 * process ("Error invoking remote method 'x': Error: …").
 */
export function stripIpcPrefix(message: string): string {
  return message.replace(REMOTE_METHOD_PREFIX, "").replace(LEADING_ERROR_NAME, "").trim();
}

/**
 * Turns a thrown value into toast copy: plain words first, the raw text kept
 * for Technical details. Network failures get friendly copy because their raw
 * form (`net::ERR_*`, `ENOTFOUND`) means nothing to most people.
 */
export function describeError(error: unknown, context: DescribeErrorContext = {}): DescribedError {
  const raw = errorText(error).trim();
  const stripped = stripIpcPrefix(raw) || raw;
  const title = context.title ?? DEFAULT_TITLE;
  const friendly = friendlyNetworkMessage(stripped, context.target);
  const message = friendly ?? ensureSentence(stripped || "An unknown error occurred.");
  return {
    title,
    message,
    technical: raw && raw !== message ? raw : undefined
  };
}

/** Shorthand for the message only, for inline error text. */
export function errorMessage(error: unknown, context?: DescribeErrorContext): string {
  return describeError(error, context).message;
}

function friendlyNetworkMessage(message: string, target = "the server"): string | undefined {
  if (/\bERR_INTERNET_DISCONNECTED\b|\bENETUNREACH\b|\bENETDOWN\b|\bEAI_AGAIN\b|\bERR_NETWORK_CHANGED\b|\bERR_ADDRESS_UNREACHABLE\b/u.test(message)) {
    return `Can't reach ${target}. Check your internet connection, then try again.`;
  }
  if (/\bERR_NAME_NOT_RESOLVED\b|\bENOTFOUND\b/u.test(message)) {
    return `Can't find ${target}. Check the address and your internet connection, then try again.`;
  }
  if (/\bECONNREFUSED\b|\bERR_CONNECTION_REFUSED\b/u.test(message)) {
    return `${capitalize(target)} refused the connection. Check the address and port, then try again.`;
  }
  if (/\bECONNRESET\b|\bERR_CONNECTION_RESET\b|\bERR_CONNECTION_CLOSED\b|socket hang up/iu.test(message)) {
    return `The connection to ${target} was cut off. Try again in a moment.`;
  }
  if (/\bETIMEDOUT\b|\bERR_TIMED_OUT\b|\bERR_CONNECTION_TIMED_OUT\b|timed out|\btimeout\b/iu.test(message)) {
    return `${capitalize(target)} took too long to answer. Check your connection, then try again.`;
  }
  if (/\bERR_CERT_|\bCERT_HAS_EXPIRED\b|\bUNABLE_TO_VERIFY_LEAF_SIGNATURE\b|self[- ]signed certificate/iu.test(message)) {
    return `The secure connection to ${target} couldn't be verified. Check the system date and try again.`;
  }
  if (/\bfetch failed\b|\bnet::ERR_[A-Z_]+/u.test(message)) {
    return `Can't reach ${target}. Check your internet connection, then try again.`;
  }
  if (/rate limit/iu.test(message)) {
    return `${capitalize(target)} is limiting requests right now. Try again in a few minutes.`;
  }
  return undefined;
}

function ensureSentence(message: string): string {
  const trimmed = message.trim();
  if (!trimmed) {
    return trimmed;
  }
  const first = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?…)]$/u.test(first) || first.includes("\n") ? first : `${first}.`;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
