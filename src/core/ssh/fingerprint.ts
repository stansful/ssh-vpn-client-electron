import { createHash } from "node:crypto";

export function sha256Fingerprint(blob: Buffer): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/u, "")}`;
}

export function md5Fingerprint(blob: Buffer): string {
  return createHash("md5")
    .update(blob)
    .digest("hex")
    .match(/.{2}/gu)!
    .join(":");
}
