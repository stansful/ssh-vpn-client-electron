import type { SshKexInit } from "./messages.js";

export interface NegotiatedAlgorithms {
  kexAlgorithm: string;
  serverHostKeyAlgorithm: string;
  encryptionClientToServer: string;
  encryptionServerToClient: string;
  macClientToServer: string;
  macServerToClient: string;
  compressionClientToServer: string;
  compressionServerToClient: string;
}

export function negotiateAlgorithms(client: SshKexInit, server: SshKexInit): NegotiatedAlgorithms {
  return {
    kexAlgorithm: chooseAlgorithm("kex", client.kexAlgorithms, server.kexAlgorithms),
    serverHostKeyAlgorithm: chooseAlgorithm("server host key", client.serverHostKeyAlgorithms, server.serverHostKeyAlgorithms),
    encryptionClientToServer: chooseAlgorithm(
      "client-to-server encryption",
      client.encryptionAlgorithmsClientToServer,
      server.encryptionAlgorithmsClientToServer
    ),
    encryptionServerToClient: chooseAlgorithm(
      "server-to-client encryption",
      client.encryptionAlgorithmsServerToClient,
      server.encryptionAlgorithmsServerToClient
    ),
    macClientToServer: chooseAlgorithm("client-to-server mac", client.macAlgorithmsClientToServer, server.macAlgorithmsClientToServer),
    macServerToClient: chooseAlgorithm("server-to-client mac", client.macAlgorithmsServerToClient, server.macAlgorithmsServerToClient),
    compressionClientToServer: chooseAlgorithm(
      "client-to-server compression",
      client.compressionAlgorithmsClientToServer,
      server.compressionAlgorithmsClientToServer
    ),
    compressionServerToClient: chooseAlgorithm(
      "server-to-client compression",
      client.compressionAlgorithmsServerToClient,
      server.compressionAlgorithmsServerToClient
    )
  };
}

/**
 * The host key type a host-key algorithm signs with, as OpenSSH names the
 * key: the three RSA signature algorithms all use one "ssh-rsa" key.
 */
export function hostKeyTypeOf(algorithm: string): string {
  return algorithm === "rsa-sha2-512" || algorithm === "rsa-sha2-256" ? "ssh-rsa" : algorithm;
}

/**
 * The host-key algorithms to ask for next when the key the server presented
 * did not match the expected fingerprint: every algorithm of the client's
 * next preferred key type that the server also offers and that has not been
 * tried yet. Undefined when no other key type is left.
 */
export function nextHostKeyAlgorithms(
  clientAlgorithms: readonly string[],
  serverAlgorithms: readonly string[],
  triedKeyTypes: ReadonlySet<string>
): string[] | undefined {
  const offered = new Set(serverAlgorithms);
  const candidates = clientAlgorithms.filter((algorithm) => offered.has(algorithm) && !triedKeyTypes.has(hostKeyTypeOf(algorithm)));
  if (candidates.length === 0) {
    return undefined;
  }
  const keyType = hostKeyTypeOf(candidates[0]);
  return candidates.filter((algorithm) => hostKeyTypeOf(algorithm) === keyType);
}

/**
 * The client's host-key algorithms with those of one key type moved to the
 * front, so a server holding that key presents it; the other types stay
 * offered behind it. Undefined when there is nothing to reorder: no type, one
 * the client does not support, or the one that already comes first.
 */
export function preferHostKeyType(clientAlgorithms: readonly string[], keyType: string | undefined): string[] | undefined {
  if (!keyType || clientAlgorithms.length === 0 || hostKeyTypeOf(clientAlgorithms[0]) === keyType) {
    return undefined;
  }
  const preferred = clientAlgorithms.filter((algorithm) => hostKeyTypeOf(algorithm) === keyType);
  if (preferred.length === 0) {
    return undefined;
  }
  return [...preferred, ...clientAlgorithms.filter((algorithm) => hostKeyTypeOf(algorithm) !== keyType)];
}

export function chooseAlgorithm(label: string, clientAlgorithms: string[], serverAlgorithms: string[]): string {
  const serverSet = new Set(serverAlgorithms);
  const match = clientAlgorithms.find((algorithm) => serverSet.has(algorithm));
  if (!match) {
    throw new Error(`No compatible SSH ${label} algorithm.`);
  }
  return match;
}
