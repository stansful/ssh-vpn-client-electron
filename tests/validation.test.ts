import { describe, expect, it } from "vitest";
import { validateDomainPattern, validateIpOrCidr, validateProcessName } from "../src/shared/validation.js";

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
});
