import net from "node:net";
import { diffieHellman, generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { negotiateAlgorithms, type NegotiatedAlgorithms } from "../src/core/ssh/algorithms.js";
import { SshBinaryReader, SshBinaryWriter } from "../src/core/ssh/binary.js";
import { sha256Fingerprint } from "../src/core/ssh/fingerprint.js";
import { encodeEd25519PublicKeyBlob, encodeRsaPublicKeyBlob, encodeSshSignatureBlob } from "../src/core/ssh/host-key.js";
import { computeCurve25519Sha256ExchangeHash, exportRawX25519PublicKey, importRawX25519PublicKey } from "../src/core/ssh/kex-curve25519.js";
import { bufferToBigInt } from "../src/core/ssh/kex-group14.js";
import { deriveDirectionalTransportKeys, transportKeyLengthsFor } from "../src/core/ssh/key-derivation.js";
import { createDefaultKexInit, decodeKexInit, encodeKexInit } from "../src/core/ssh/messages.js";
import type { PacketProtectionConfig } from "../src/core/ssh/packet-codec.js";
import { SshSocketTransport } from "../src/core/ssh/socket-transport.js";

/**
 * A small SSH server for handshake tests: curve25519 key exchange with an
 * Ed25519 and an RSA host key, "ssh-userauth" that accepts anything, and
 * direct-tcpip channels that only confirm. Each connection records what the
 * client asked for, so tests can check the client's side of the protocol.
 */

export interface FakeHostKey {
  privateKey: KeyObject;
  blob: Buffer;
  fingerprint: string;
}

export interface FakeHostKeys {
  ed25519: FakeHostKey;
  rsa: FakeHostKey;
}

export function createFakeHostKeys(): FakeHostKeys {
  const ed25519 = generateKeyPairSync("ed25519");
  const ed25519Blob = encodeEd25519PublicKeyBlob(ed25519.publicKey.export({ format: "der", type: "spki" }).subarray(-32));
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaJwk = rsa.publicKey.export({ format: "jwk" });
  const rsaBlob = encodeRsaPublicKeyBlob(
    bufferToBigInt(Buffer.from(rsaJwk.n!, "base64url")),
    bufferToBigInt(Buffer.from(rsaJwk.e!, "base64url"))
  );
  return {
    ed25519: { privateKey: ed25519.privateKey, blob: ed25519Blob, fingerprint: sha256Fingerprint(ed25519Blob) },
    rsa: { privateKey: rsa.privateKey, blob: rsaBlob, fingerprint: sha256Fingerprint(rsaBlob) }
  };
}

export interface FakeServerOptions {
  hostKeys: FakeHostKeys;
  /** Host-key algorithms the server's KEXINIT advertises. */
  hostKeyAlgorithms?: string[];
  /** Per connection (0-based): where the server stops answering. */
  stall?: (connectionIndex: number) => "identification" | "kex-reply" | "auth" | undefined;
  /** Called when a client KEXINIT arrives, before the server answers it. */
  onClientKexInit?: (connection: FakeConnectionLog) => void;
  /**
   * CHANNEL_DATA packets of `bytes` each the server still sends on the open
   * channel after a client-initiated rekey began and before its own KEXINIT,
   * as a server does while the client's KEXINIT is in flight.
   */
  rekeyBurst?: { packets: number; bytes: number };
}

export interface FakeConnectionLog {
  index: number;
  identified: boolean;
  clientHostKeyAlgorithms: string[][];
  negotiatedHostKeyAlgorithms: string[];
  serviceRequested: boolean;
  authenticated: boolean;
  keyExchanges: number;
  windowAdjusts: number;
  /** Messages other than transport/KEX ones received between a client KEXINIT and its NEWKEYS. */
  kexViolations: number[];
  closed: Promise<void>;
}

export class FakeSshServer {
  readonly connections: FakeConnectionLog[] = [];
  private readonly server: net.Server;
  private readonly sockets = new Set<net.Socket>();

  private constructor(private readonly options: FakeServerOptions) {
    this.server = net.createServer((socket) => this.accept(socket));
  }

  static async start(options: FakeServerOptions): Promise<FakeSshServer> {
    const server = new FakeSshServer(options);
    await new Promise<void>((resolve) => server.server.listen(0, "127.0.0.1", resolve));
    return server;
  }

  get port(): number {
    return (this.server.address() as net.AddressInfo).port;
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) {
      socket.destroy();
    }
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private accept(socket: net.Socket): void {
    this.sockets.add(socket);
    let markClosed!: () => void;
    const log: FakeConnectionLog = {
      index: this.connections.length,
      identified: false,
      clientHostKeyAlgorithms: [],
      negotiatedHostKeyAlgorithms: [],
      serviceRequested: false,
      authenticated: false,
      keyExchanges: 0,
      windowAdjusts: 0,
      kexViolations: [],
      closed: new Promise<void>((resolve) => {
        markClosed = resolve;
      })
    };
    this.connections.push(log);
    socket.on("close", () => {
      this.sockets.delete(socket);
      markClosed();
    });
    socket.on("error", () => undefined);
    if (this.options.stall?.(log.index) === "identification") {
      // Read and drop, so the client's close still reaches "close" here.
      socket.resume();
      return;
    }
    void new FakeServerConnection(socket, log, this.options).run().catch(() => socket.destroy());
  }
}

class FakeServerConnection {
  private readonly transport: SshSocketTransport;
  private clientLine = "";
  private serverLine = "";
  private serverKexInitPayload: Buffer | undefined;
  private clientKexInitPayload: Buffer | undefined;
  private negotiated: NegotiatedAlgorithms | undefined;
  private sessionId: Buffer | undefined;
  private clientInKex = false;
  private runtime = false;
  private clientChannel: number | undefined;
  private work: Promise<void> = Promise.resolve();
  private readonly stall: ReturnType<NonNullable<FakeServerOptions["stall"]>>;

  constructor(
    private readonly socket: net.Socket,
    private readonly log: FakeConnectionLog,
    private readonly options: FakeServerOptions
  ) {
    this.transport = SshSocketTransport.fromSocket(socket);
    this.stall = options.stall?.(log.index);
  }

  async run(): Promise<void> {
    const identification = await this.transport.exchangeIdentification("FakeServer_1.0", 10_000);
    this.serverLine = identification.clientLine;
    this.clientLine = identification.serverLine;
    this.log.identified = true;
    this.transport.onEvent((event) => {
      if (event.type === "payload") {
        const payload = event.payload;
        this.work = this.work.then(() => this.handle(payload)).catch(() => {
          this.socket.destroy();
        });
      }
    });
    await this.sendKexInit();
  }

  private async sendKexInit(): Promise<void> {
    this.serverKexInitPayload = encodeKexInit({
      ...createDefaultKexInit(),
      kexAlgorithms: ["curve25519-sha256"],
      serverHostKeyAlgorithms: this.options.hostKeyAlgorithms ?? ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]
    });
    await this.transport.sendOwned(this.serverKexInitPayload);
  }

  private async handle(payload: Buffer): Promise<void> {
    const number = payload[0];
    if (this.clientInKex && number > 49) {
      this.log.kexViolations.push(number);
    }
    switch (number) {
      case 20:
        await this.receiveKexInit(payload);
        return;
      case 30:
        await this.receiveKexEcdhInit(payload);
        return;
      case 21:
        this.clientInKex = false;
        this.log.keyExchanges += 1;
        if (this.runtime) {
          this.transport.finishRuntimeKeyExchange();
        }
        this.runtime = true;
        return;
      case 5:
        this.log.serviceRequested = true;
        await this.transport.sendOwned(new SshBinaryWriter().byte(6).string("ssh-userauth").toBuffer());
        return;
      case 50:
        if (this.stall === "auth") {
          return;
        }
        this.log.authenticated = true;
        await this.transport.sendOwned(Buffer.from([52]));
        return;
      case 90: {
        const reader = new SshBinaryReader(payload);
        reader.byte();
        reader.utf8String();
        this.clientChannel = reader.uint32();
        await this.transport.sendOwned(
          new SshBinaryWriter().byte(91).uint32(this.clientChannel).uint32(0).uint32(1024 * 1024).uint32(32 * 1024).toBuffer()
        );
        return;
      }
      case 93:
        this.log.windowAdjusts += 1;
        return;
      default:
    }
  }

  private async receiveKexInit(payload: Buffer): Promise<void> {
    this.clientInKex = true;
    this.clientKexInitPayload = payload;
    const clientKexInit = decodeKexInit(payload);
    this.log.clientHostKeyAlgorithms.push(clientKexInit.serverHostKeyAlgorithms);
    this.options.onClientKexInit?.(this.log);
    if (this.runtime) {
      // A client-initiated rekey: until our own KEXINIT the old keys still
      // carry channel data, and a busy server keeps sending it.
      const burst = this.options.rekeyBurst;
      if (burst && this.clientChannel !== undefined) {
        for (let index = 0; index < burst.packets; index += 1) {
          await this.transport.sendOwned(
            new SshBinaryWriter().byte(94).uint32(this.clientChannel).string(Buffer.alloc(burst.bytes, index & 0xff)).toBuffer()
          );
        }
      }
      await this.sendKexInit();
      this.transport.beginRuntimeKeyExchange();
    }
    this.negotiated = negotiateAlgorithms(clientKexInit, decodeKexInit(this.serverKexInitPayload!));
    this.log.negotiatedHostKeyAlgorithms.push(this.negotiated.serverHostKeyAlgorithm);
  }

  private async receiveKexEcdhInit(payload: Buffer): Promise<void> {
    if (this.stall === "kex-reply") {
      return;
    }
    const negotiated = this.negotiated!;
    const reader = new SshBinaryReader(payload);
    reader.byte();
    const clientPublicKey = reader.string();
    const exchange = generateKeyPairSync("x25519");
    const serverPublicKey = exportRawX25519PublicKey(exchange.publicKey);
    const sharedSecret = bufferToBigInt(
      diffieHellman({ privateKey: exchange.privateKey, publicKey: importRawX25519PublicKey(clientPublicKey) })
    );
    const hostKey = negotiated.serverHostKeyAlgorithm === "ssh-ed25519" ? this.options.hostKeys.ed25519 : this.options.hostKeys.rsa;
    const exchangeHash = computeCurve25519Sha256ExchangeHash({
      clientVersion: this.clientLine,
      serverVersion: this.serverLine,
      clientKexInitPayload: this.clientKexInitPayload!,
      serverKexInitPayload: this.serverKexInitPayload!,
      serverHostKey: hostKey.blob,
      clientPublicKey,
      serverPublicKey,
      sharedSecret
    });
    this.sessionId ??= exchangeHash;
    const signature = signExchangeHash(negotiated.serverHostKeyAlgorithm, hostKey.privateKey, exchangeHash);
    const keys = deriveDirectionalTransportKeys(
      sharedSecret,
      exchangeHash,
      this.sessionId,
      transportKeyLengthsFor(negotiated.encryptionClientToServer, negotiated.macClientToServer),
      transportKeyLengthsFor(negotiated.encryptionServerToClient, negotiated.macServerToClient)
    );
    this.transport.prepareInboundEncryption({
      cipherName: negotiated.encryptionClientToServer as PacketProtectionConfig["cipherName"],
      encryptionKey: keys.encryptionKeyClientToServer,
      initialIv: keys.initialIvClientToServer,
      macName: negotiated.macClientToServer as PacketProtectionConfig["macName"],
      macKey: keys.integrityKeyClientToServer
    });
    await this.transport.sendOwned(
      new SshBinaryWriter().byte(31).string(hostKey.blob).string(serverPublicKey).string(signature).toBuffer()
    );
    await this.transport.sendOwned(Buffer.from([21]));
    this.transport.enableOutboundEncryption({
      cipherName: negotiated.encryptionServerToClient as PacketProtectionConfig["cipherName"],
      encryptionKey: keys.encryptionKeyServerToClient,
      initialIv: keys.initialIvServerToClient,
      macName: negotiated.macServerToClient as PacketProtectionConfig["macName"],
      macKey: keys.integrityKeyServerToClient
    });
  }
}

function signExchangeHash(algorithm: string, privateKey: KeyObject, exchangeHash: Buffer): Buffer {
  if (algorithm === "ssh-ed25519") {
    return encodeSshSignatureBlob(algorithm, nodeSign(null, exchangeHash, privateKey));
  }
  return encodeSshSignatureBlob(algorithm, nodeSign(algorithm === "rsa-sha2-512" ? "sha512" : "sha256", exchangeHash, privateKey));
}
