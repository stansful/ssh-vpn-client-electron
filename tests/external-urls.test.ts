import { describe, expect, it } from "vitest";
import { assertAllowedExternalUrl } from "../src/main/app/external-urls.js";
import { GITHUB_REPOSITORY_URL, ROUTING_DOMAIN_LIST_SOURCE_URL } from "../src/shared/links.js";

describe("external URL allow-list", () => {
  it("opens the repository, the domain list source and this repository's release pages", () => {
    expect(assertAllowedExternalUrl(GITHUB_REPOSITORY_URL)).toBe(GITHUB_REPOSITORY_URL);
    expect(assertAllowedExternalUrl(`${GITHUB_REPOSITORY_URL}/`)).toBe(`${GITHUB_REPOSITORY_URL}/`);
    expect(assertAllowedExternalUrl(ROUTING_DOMAIN_LIST_SOURCE_URL)).toBe(ROUTING_DOMAIN_LIST_SOURCE_URL);
    expect(assertAllowedExternalUrl(`${GITHUB_REPOSITORY_URL}/releases`)).toBe(`${GITHUB_REPOSITORY_URL}/releases`);
    expect(assertAllowedExternalUrl(`${GITHUB_REPOSITORY_URL}/releases/tag/v2.3.0`)).toBe(`${GITHUB_REPOSITORY_URL}/releases/tag/v2.3.0`);
  });

  it("refuses everything else", () => {
    for (const url of [
      "http://github.com/stansful/ssh-vpn-client-electron",
      `${GITHUB_REPOSITORY_URL}/issues`,
      `${GITHUB_REPOSITORY_URL}-evil/releases`,
      `${GITHUB_REPOSITORY_URL}/releasesX`,
      "https://user:pass@github.com/stansful/ssh-vpn-client-electron/releases",
      "https://evil.example/stansful/ssh-vpn-client-electron/releases",
      "file:///etc/passwd",
      "javascript:alert(1)"
    ]) {
      expect(() => assertAllowedExternalUrl(url), url).toThrow("External URL is not allowed.");
    }
  });
});
