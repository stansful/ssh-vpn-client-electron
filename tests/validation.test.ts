import { describe, expect, it } from "vitest";
import {
  CHECK_ENDPOINT_FORMAT_MESSAGE,
  validateCheckEndpoint,
  validateDomainPattern,
  validateIpOrCidr,
  validateProcessName,
  validateSshServerFingerprint
} from "../src/shared/validation.js";

describe("routing rule validation", () => {
  it("accepts exact and wildcard domain patterns", () => {
    expect(validateDomainPattern("youtube.com").ok).toBe(true);
    expect(validateDomainPattern("*.googlevideo.com").ok).toBe(true);
  });

  it("rejects invalid domain patterns", () => {
    expect(validateDomainPattern("localhost").ok).toBe(false);
    expect(validateDomainPattern("-bad.example.com").ok).toBe(false);
    expect(validateDomainPattern("bad..example.com").ok).toBe(false);
  });

  it("accepts IPv4, IPv6, and CIDR ranges", () => {
    expect(validateIpOrCidr("8.8.8.8").ok).toBe(true);
    expect(validateIpOrCidr("142.250.0.0/15").ok).toBe(true);
    expect(validateIpOrCidr("2a00:1450::/32").ok).toBe(true);
  });

  it("rejects invalid IP and CIDR values", () => {
    expect(validateIpOrCidr("999.1.1.1").ok).toBe(false);
    expect(validateIpOrCidr("1.1.1.1/33").ok).toBe(false);
    expect(validateIpOrCidr("2a00:1450::/129").ok).toBe(false);
  });

  it("accepts process names and rejects paths", () => {
    expect(validateProcessName("chrome.exe").ok).toBe(true);
    expect(validateProcessName("Google Chrome").ok).toBe(true);
    expect(validateProcessName("C:\\Windows\\notepad.exe").ok).toBe(false);
  });

  it("validates OpenSSH SHA256 server fingerprint pins", () => {
    expect(validateSshServerFingerprint(`SHA256:${"A".repeat(43)}`).ok).toBe(true);
    expect(validateSshServerFingerprint("").ok).toBe(true);
    expect(validateSshServerFingerprint("", false).ok).toBe(false);
    expect(validateSshServerFingerprint("sha256:not-a-pin").ok).toBe(false);
  });
});

describe("tunnel check endpoint validation", () => {
  it("accepts host:port with a name, an IPv4 address or a bracketed IPv6 address", () => {
    for (const endpoint of [
      "youtube.com:443",
      " youtube.com:443 ",
      "db.example.org:5432",
      "localhost:8080",
      "1.1.1.1:53",
      "[2606:4700::1111]:443",
      "[::1]:80",
      "пример.рф:443",
      "example.com.:443"
    ]) {
      expect(validateCheckEndpoint(endpoint), endpoint).toEqual({ ok: true });
    }
  });

  it("asks for host:port instead of a link when given a scheme, a path or credentials", () => {
    for (const endpoint of [
      "https://youtube.com",
      "https://youtube.com:443",
      "tcp://youtube.com:443",
      "youtube.com/watch",
      "youtube.com:443/",
      "/youtube.com:443",
      "user@youtube.com:443",
      "youtube.com:443?x=1",
      "youtube.com:443#top"
    ]) {
      expect(validateCheckEndpoint(endpoint), endpoint).toEqual({ ok: false, message: CHECK_ENDPOINT_FORMAT_MESSAGE });
    }
    expect(CHECK_ENDPOINT_FORMAT_MESSAGE).toBe("Enter host:port without https:// or a path — for example youtube.com:443.");
  });

  it("keeps the existing messages for an empty value, a bad host and a bad port", () => {
    expect(validateCheckEndpoint("  ")).toEqual({ ok: false, message: "Endpoint is required. Use host:port." });
    for (const endpoint of ["youtube.com", "youtube.com:", "youtube.com:0", "youtube.com:65536", "youtube.com:https", "[::1]"]) {
      expect(validateCheckEndpoint(endpoint), endpoint).toEqual({
        ok: false,
        message: "Endpoint must use host:port with a valid TCP port."
      });
    }
    for (const endpoint of ["bad host:443", "-bad.example.com:443", "bad..example.com:443", "999.1.1.1:443", "2001:db8::1:443", "[zz]:443", ":443"]) {
      expect(validateCheckEndpoint(endpoint), endpoint).toEqual({
        ok: false,
        message: "Endpoint must use host:port, for example youtube.com:443."
      });
    }
  });
});
