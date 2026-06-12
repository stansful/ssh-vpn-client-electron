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

export function chooseAlgorithm(label: string, clientAlgorithms: string[], serverAlgorithms: string[]): string {
  const serverSet = new Set(serverAlgorithms);
  const match = clientAlgorithms.find((algorithm) => serverSet.has(algorithm));
  if (!match) {
    throw new Error(`No compatible SSH ${label} algorithm.`);
  }
  return match;
}
