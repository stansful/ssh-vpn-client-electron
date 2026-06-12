export interface ParsedSshVersion {
  protocol: string;
  software: string;
  comments?: string;
  raw: string;
}

export const CLIENT_SOFTWARE_VERSION = "shadow-ssh-desktop_0.1";

export function formatClientVersion(software = CLIENT_SOFTWARE_VERSION): string {
  if (!/^[A-Za-z0-9._+-]+$/.test(software)) {
    throw new Error("SSH software version contains unsupported characters.");
  }
  return `SSH-2.0-${software}\r\n`;
}

export function parseSshVersionLine(line: string): ParsedSshVersion {
  const raw = line.replace(/\r?\n$/, "");
  if (!raw.startsWith("SSH-")) {
    throw new Error("Not an SSH version line.");
  }

  const firstDash = raw.indexOf("-");
  const secondDash = raw.indexOf("-", firstDash + 1);
  if (firstDash < 0 || secondDash < 0) {
    throw new Error("Malformed SSH version line.");
  }

  const protocol = raw.slice(firstDash + 1, secondDash);
  const rest = raw.slice(secondDash + 1);
  const spaceIndex = rest.indexOf(" ");
  const software = spaceIndex >= 0 ? rest.slice(0, spaceIndex) : rest;
  const comments = spaceIndex >= 0 ? rest.slice(spaceIndex + 1) : undefined;

  if (protocol !== "2.0") {
    throw new Error(`Unsupported SSH protocol ${protocol}.`);
  }
  if (!software) {
    throw new Error("SSH software version is empty.");
  }

  return {
    protocol,
    software,
    comments,
    raw
  };
}
