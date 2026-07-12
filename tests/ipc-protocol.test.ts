import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { MAX_DIAGNOSTIC_MESSAGE_BYTES } from "../src/shared/diagnostics-history.js";
import {
  BoundedUtf8LineDecoder,
  decodeWireMessage,
  defaultServiceEndpoint,
  encodeWireMessage,
  isNativeServiceHandshake,
  isRuntimeStatusPayload,
  MAX_SERVICE_AUTH_TOKEN_LENGTH,
  MAX_SERVICE_ENDPOINT_WIRE_BYTES,
  MAX_SERVICE_WIRE_BYTES,
  MAX_SERVICE_MESSAGE_ID_LENGTH,
  requestTimeoutMs,
  SERVICE_CONNECT_TIMEOUT_MS,
  SERVICE_DEFAULT_REQUEST_TIMEOUT_MS,
  SERVICE_LONG_REQUEST_TIMEOUT_MS,
  SERVICE_PROTOCOL_VERSION,
  ServiceProtocolError,
  ServiceWireDecoder,
  writeWithBackpressure
} from "../src/service/local-ipc-protocol.js";

describe("local IPC protocol", () => {
  it("round-trips versioned JSON-line service commands", () => {
    const encoded = encodeWireMessage({ id: "1", type: "disconnect" });
    expect(encoded.endsWith("\n")).toBe(true);
    expect(decodeWireMessage(encoded.trim())).toEqual({
      id: "1",
      protocolVersion: SERVICE_PROTOCOL_VERSION,
      type: "disconnect"
    });
  });

  it("rejects missing and incompatible protocol versions", () => {
    expect(() => decodeWireMessage('{"id":"1","type":"disconnect"}')).toThrow(ServiceProtocolError);
    expect(() => decodeWireMessage('{"protocolVersion":2,"id":"1","type":"disconnect"}')).toThrow(
      /expected 1/u
    );
  });

  it("bounds command and response correlation identifiers", () => {
    const oversizedId = "x".repeat(MAX_SERVICE_MESSAGE_ID_LENGTH + 1);
    expect(() => decodeWireMessage(JSON.stringify({ protocolVersion: 1, id: oversizedId, type: "disconnect" }))).toThrow(
      /Malformed service command/u
    );
    expect(() => decodeWireMessage(JSON.stringify({ protocolVersion: 1, kind: "response", id: oversizedId, ok: true }))).toThrow(
      /Malformed service response/u
    );
    expect(() =>
      decodeWireMessage(JSON.stringify({
        protocolVersion: 1,
        id: "1",
        type: "disconnect",
        authToken: "x".repeat(MAX_SERVICE_AUTH_TOKEN_LENGTH + 1)
      }))
    ).toThrow(/Malformed service command/u);
  });

  it("rejects malformed event payloads instead of trusting envelope types", () => {
    expect(() =>
      decodeWireMessage(JSON.stringify({
        protocolVersion: SERVICE_PROTOCOL_VERSION,
        kind: "event",
        event: { type: "status-changed", status: { state: "Connected" } }
      }))
    ).toThrow(/Malformed service event/u);
    expect(() =>
      decodeWireMessage(JSON.stringify({
        protocolVersion: SERVICE_PROTOCOL_VERSION,
        kind: "event",
        event: {
          type: "diagnostics-appended",
          entry: {
            id: "diagnostic",
            at: "now",
            level: "warning",
            message: "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES + 1)
          }
        }
      }))
    ).toThrow(/Malformed service event/u);
  });

  it("validates runtime status enums, counters, and platform targets", () => {
    const valid = {
      state: "Disconnected",
      message: "Ready",
      reconnectAttempt: 0,
      transport: "native-ipc",
      realTunnelAvailable: false,
      platformTarget: {
        platform: "windows",
        arch: "x64",
        serviceExecutableName: "shadow-ssh-service.exe",
        serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
        supportsPrivilegedService: true
      }
    };
    expect(isRuntimeStatusPayload(valid)).toBe(true);
    expect(isRuntimeStatusPayload({ ...valid, state: "Compromised" })).toBe(false);
    expect(isRuntimeStatusPayload({ ...valid, reconnectAttempt: -1 })).toBe(false);
    expect(isRuntimeStatusPayload({ ...valid, platformTarget: { ...valid.platformTarget, arch: "mips" } })).toBe(false);
  });

  it("validates an explicit fail-closed native capability handshake", () => {
    expect(
      isNativeServiceHandshake({
        protocolVersion: SERVICE_PROTOCOL_VERSION,
        capabilities: {
          target: {
            platform: "windows",
            arch: "x64",
            serviceExecutableName: "shadow-ssh-service.exe",
            serviceRelativePath: "native/windows/x64/shadow-ssh-service.exe",
            supportsPrivilegedService: true
          },
          ipc: "named-pipe-or-stdio",
          namedPipeAcl: true,
          unixSocketMode: false,
          serviceControlManager: true,
          wfpInterception: false,
          tunDevice: false,
          routeManipulation: false,
          processConnectionAttribution: true,
          dnsVisibility: false,
          ipv6RouteEnforcement: false,
          udpForwarding: false,
          sshCoreLinked: false
        }
      })
    ).toBe(true);
    expect(isNativeServiceHandshake({ protocolVersion: 1, capabilities: { sshCoreLinked: false } })).toBe(false);
  });

  it("decodes split multibyte UTF-8 without replacement characters", () => {
    const decoder = new ServiceWireDecoder();
    const encoded = Buffer.from(
      encodeWireMessage({
        kind: "event",
        event: {
          type: "error",
          message: "Ошибка туннеля"
        }
      }),
      "utf8"
    );
    const multibyteStart = encoded.indexOf(Buffer.from("О", "utf8"));
    const messages = [
      ...decoder.push(encoded.subarray(0, multibyteStart + 1)),
      ...decoder.push(encoded.subarray(multibyteStart + 1))
    ];
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({
      kind: "event",
      event: { message: "Ошибка туннеля" }
    });
  });

  it("bounds incomplete lines and encoded frames", () => {
    const decoder = new BoundedUtf8LineDecoder(4, "test line");
    expect(() => decoder.push(Buffer.from("12345", "utf8"))).toThrow(/exceeds 4 bytes/u);
    expect(() =>
      encodeWireMessage({ id: "1", type: "terminal-input", payload: { input: "x".repeat(MAX_SERVICE_WIRE_BYTES) } })
    ).toThrow(ServiceProtocolError);
    const endpointDecoder = new ServiceWireDecoder(MAX_SERVICE_ENDPOINT_WIRE_BYTES);
    expect(() => endpointDecoder.push(Buffer.alloc(MAX_SERVICE_ENDPOINT_WIRE_BYTES + 1, 0x78))).toThrow(
      /endpoint|frame|exceeds/iu
    );
  });

  it("uses bounded command-specific request deadlines", () => {
    expect(requestTimeoutMs("get-status")).toBe(SERVICE_CONNECT_TIMEOUT_MS);
    expect(requestTimeoutMs("get-capabilities")).toBe(SERVICE_CONNECT_TIMEOUT_MS);
    expect(requestTimeoutMs("connect")).toBe(SERVICE_LONG_REQUEST_TIMEOUT_MS);
    expect(requestTimeoutMs("disconnect")).toBe(SERVICE_DEFAULT_REQUEST_TIMEOUT_MS);
  });

  it("waits for stream backpressure before resolving", async () => {
    let completed = false;
    const writer = new Writable({
      highWaterMark: 1,
      write(_chunk, _encoding, callback) {
        setTimeout(() => {
          completed = true;
          callback();
        }, 10);
      }
    });
    await writeWithBackpressure(writer, "payload");
    expect(completed).toBe(true);
    writer.destroy();
  });

  it("still waits for drain when a writer invokes its callback synchronously", async () => {
    const writer = Object.assign(new EventEmitter(), {
      destroyed: false,
      writable: true,
      write(_data: string, _encoding: string, callback: (error?: Error | null) => void): boolean {
        callback();
        return false;
      }
    }) as unknown as Writable;
    let resolved = false;

    const pending = writeWithBackpressure(writer, "payload").then(() => {
      resolved = true;
    });
    await Promise.resolve();
    expect(resolved).toBe(false);

    writer.emit("drain");
    await pending;
    expect(resolved).toBe(true);
  });

  it("uses a local endpoint shape", () => {
    const endpoint = defaultServiceEndpoint("shadow-ssh-test");
    expect(endpoint).toContain("shadow-ssh-test");
    expect(endpoint.startsWith("\\\\.\\pipe\\") || endpoint.endsWith(".sock")).toBe(true);
  });
});
