import { describe, expect, it } from "vitest";
import { decodeWireMessage, defaultServiceEndpoint, encodeWireMessage } from "../src/service/local-ipc-protocol.js";

describe("local IPC protocol", () => {
  it("round-trips JSON-line service commands", () => {
    const encoded = encodeWireMessage({ id: "1", type: "disconnect" });
    expect(encoded.endsWith("\n")).toBe(true);
    expect(decodeWireMessage(encoded.trim())).toEqual({ id: "1", type: "disconnect" });
  });

  it("uses a local endpoint shape", () => {
    const endpoint = defaultServiceEndpoint("shadow-ssh-test");
    expect(endpoint).toContain("shadow-ssh-test");
    expect(endpoint.startsWith("\\\\.\\pipe\\") || endpoint.endsWith(".sock")).toBe(true);
  });
});
