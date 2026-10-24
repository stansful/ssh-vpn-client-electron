import { describe, expect, it } from "vitest";
import { unpinnedRemovalEndsSession } from "../src/main/app/profile-removal.js";

const profiles = [
  { id: "pinned", isPinned: true },
  { id: "loose", isPinned: false }
];

describe("Remove unpinned and the running Xray session", () => {
  it("keeps a session whose profile is pinned", () => {
    expect(unpinnedRemovalEndsSession({ activeTransport: "xray", activeProfileId: "pinned", profiles })).toBe(false);
  });

  it("ends the session whose profile it removes", () => {
    expect(unpinnedRemovalEndsSession({ activeTransport: "xray", activeProfileId: "loose", profiles })).toBe(true);
  });

  it("leaves SSH, an idle Xray and a profile already gone alone", () => {
    expect(unpinnedRemovalEndsSession({ activeTransport: "ssh", activeProfileId: "loose", profiles })).toBe(false);
    expect(unpinnedRemovalEndsSession({ activeTransport: "xray", activeProfileId: undefined, profiles })).toBe(false);
    expect(unpinnedRemovalEndsSession({ activeTransport: "xray", activeProfileId: "deleted", profiles })).toBe(false);
  });
});
