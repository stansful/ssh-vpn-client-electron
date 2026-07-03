export function validateEndpointInput(value: string): { ok: true } | { ok: false; message: string } {
  const trimmed = value.trim();
  if (!trimmed) {
    return { ok: false, message: "Endpoint is required. Use host:port." };
  }
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed) ? trimmed : `tcp://${trimmed}`;
    const url = new URL(withScheme);
    const port = Number(url.port);
    if (!url.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
      return { ok: false, message: "Endpoint must use host:port with a valid TCP port." };
    }
    return { ok: true };
  } catch {
    return { ok: false, message: "Endpoint must use host:port, for example youtube.com:443." };
  }
}
