import { describe, expect, it } from "vitest";
import {
  bulkRemoveCopy,
  copiedLinkCopy,
  copyLinkFailedCopy,
  countProfiles,
  currentSelection,
  describeRefreshFailure,
  filterProfiles,
  fixedInsecureCopy,
  insecureProfileFixedBy,
  moreBlockCopy,
  noMatchCopy,
  presentProfileCard,
  publicListInfo,
  publicListMeta,
  removeBlockedCopy,
  removedOneCopy,
  removedUnpinnedCopy,
  renamedNotice,
  renameFailedTitle,
  resultsSummary,
  savedProfileCopy,
  singleRemoveCopy,
  sourceLabel,
  summarizeRefresh,
  unsupportedSelectCopy,
  xraySessionOf,
  type XraySession
} from "../src/renderer/components/pages/profiles/profile-presenter.js";
import { HYSTERIA2_INSECURE_PROFILE_WARNING, previewShareLink, type LinkPreview } from "../src/renderer/components/pages/profiles/link-preview.js";
import { createDefaultStore } from "../src/shared/defaults.js";
import type { AppStore, ProxyProfile, RuntimeStatus } from "../src/shared/types.js";

function profile(overrides: Partial<ProxyProfile>): ProxyProfile {
  return {
    id: "p1",
    name: "de-fra-reality",
    protocol: "vless",
    host: "185.244.30.9",
    port: 443,
    transport: "tcp",
    security: "reality",
    flow: "",
    source: "manual",
    rawUriSecretId: "secret",
    fingerprint: "sha256:0",
    isSelected: false,
    isPinned: false,
    isStale: false,
    lastTestStatus: "unknown",
    createdAt: "2026-10-06T09:00:00.000Z",
    updatedAt: "2026-10-06T09:00:00.000Z",
    lastSeenAt: "2026-10-06T09:00:00.000Z",
    ...overrides
  };
}

function runtime(overrides: Partial<RuntimeStatus>): RuntimeStatus {
  return {
    state: "Disconnected",
    message: "Disconnected.",
    reconnectAttempt: 0,
    transport: "xray",
    platformTarget: { platform: "windows", arch: "x64", serviceExecutableName: "shadow-ssh-service.exe", serviceRelativePath: "service", supportsPrivilegedService: true },
    realTunnelAvailable: true,
    ...overrides
  };
}

function store(profiles: ProxyProfile[], selectedProxyProfileId?: string): AppStore {
  return { ...createDefaultStore(), proxyProfiles: profiles, selectedProxyProfileId };
}

const fra = profile({ id: "fra", name: "de-fra-reality", isPinned: true });
const ams = profile({ id: "ams", name: "nl-ams-ws", protocol: "vmess", host: "ams.example.org", transport: "ws", security: "tls", source: "clipboard" });
const gone = profile({ id: "gone", name: "public-23", host: "45.12.33.1", port: 8443, transport: "grpc", security: "tls", source: "remote", isStale: true });
const lab = profile({ id: "lab", name: "lab-unknown", host: "192.0.2.9", security: "unknown" });
const v6 = profile({ id: "v6", name: "warsaw-v6", host: "2001:db8::1", transport: "ws", security: "tls", source: "clipboard" });
const hel = profile({
  id: "hel",
  name: "fi-hel-hy2",
  protocol: "hysteria2",
  host: "hel.example.net",
  port: 443,
  hopPorts: "443,20000-30000",
  transport: "hysteria",
  security: "tls",
  source: "clipboard"
});
const hy = profile({ id: "hy", name: "hy-single", protocol: "hysteria2", host: "2001:db8::7", port: 8443, transport: "hysteria", security: "tls" });

describe("profile library", () => {
  it("counts pinned, gone and unpinned profiles", () => {
    expect(countProfiles([fra, ams, gone, lab, profile({ id: "g2", isStale: true, isPinned: true })])).toEqual({ all: 5, pinned: 2, gone: 2, goneUnpinned: 1, unpinned: 3 });
  });

  it("labels sources the way the board does", () => {
    expect(sourceLabel("manual")).toBe("Added by you");
    expect(sourceLabel("clipboard")).toBe("Imported");
    expect(sourceLabel("remote")).toBe("Public");
  });

  it("searches names, hosts, ports, protocols, transports and sources within a filter", () => {
    const all = [fra, ams, gone, lab, v6];
    expect(filterProfiles(all, "all", "VMESS").map((item) => item.id)).toEqual(["ams"]);
    expect(filterProfiles(all, "all", "8443").map((item) => item.id)).toEqual(["gone"]);
    expect(filterProfiles(all, "all", "[2001:db8::1]:443").map((item) => item.id)).toEqual(["v6"]);
    expect(filterProfiles(all, "all", "public").map((item) => item.id)).toEqual(["gone"]);
    expect(filterProfiles(all, "pinned", "").map((item) => item.id)).toEqual(["fra"]);
    expect(filterProfiles(all, "gone", "ws").map((item) => item.id)).toEqual([]);
  });

  it("finds Hysteria 2 profiles by label, scheme, quic and hop ports", () => {
    const all = [fra, ams, hel, hy, profile({ id: "vh", name: "vless-hysteria", transport: "hysteria", security: "tls" })];
    expect(filterProfiles(all, "all", "Hysteria 2").map((item) => item.id)).toEqual(["hel", "hy"]);
    expect(filterProfiles(all, "all", "hysteria2").map((item) => item.id)).toEqual(["hel", "hy"]);
    expect(filterProfiles(all, "all", "HY2").map((item) => item.id)).toEqual(["hel", "hy"]);
    expect(filterProfiles(all, "all", "quic").map((item) => item.id)).toEqual(["hel", "hy"]);
    expect(filterProfiles(all, "all", "20000-30000").map((item) => item.id)).toEqual(["hel"]);
    expect(filterProfiles(all, "all", "hel.example.net:443,20000").map((item) => item.id)).toEqual(["hel"]);
    expect(filterProfiles(all, "all", "[2001:db8::7]:8443").map((item) => item.id)).toEqual(["hy"]);
    expect(filterProfiles(all, "all", "hysteria").map((item) => item.id)).toEqual(["hel", "hy", "vh"]);
  });
});

describe("Xray session and cards", () => {
  it("only reports a session Xray owns and runs", () => {
    expect(xraySessionOf("ssh", runtime({ state: "Connected", activeConfigId: "fra" }))).toBeUndefined();
    expect(xraySessionOf("xray", runtime({ state: "Error", activeConfigId: "fra" }))).toBeUndefined();
    expect(xraySessionOf("xray", runtime({ state: "Connected", activeConfigId: "fra", activeConfigName: "de-fra-reality" }))).toEqual({ phase: "connected", profileId: "fra", name: "de-fra-reality" });
    expect(xraySessionOf("xray", runtime({ state: "Connected", activeConfigId: "fra", transport: "simulator" }))?.phase).toBe("preview");
    expect(xraySessionOf("xray", runtime({ state: "Reconnecting", activeConfigId: "fra" }))?.phase).toBe("reconnecting");
  });

  it("shows the selected profile and the next-connect hand-over", () => {
    expect(presentProfileCard(fra, { selectedId: "fra" }).state).toEqual({ label: "Selected for Connect", tone: "accent", glyph: "check" });
    const session: XraySession = { phase: "connected", profileId: "ams" };
    expect(presentProfileCard(fra, { selectedId: "fra", session }).state?.label).toBe("Selected · next connect");
    expect(presentProfileCard(gone, { selectedId: "gone" }).state?.label).toBe("Selected for now");
    expect(presentProfileCard(ams, { selectedId: "fra" })).toMatchObject({ state: undefined, hint: "Select for Connect", protoTone: "outline", hitLabel: "Select nl-ams-ws for Connect" });
  });

  it("marks the profile carrying traffic and blocks removing it", () => {
    const view = presentProfileCard(fra, { selectedId: "fra", session: { phase: "connected", profileId: "fra" } });
    expect(view).toMatchObject({
      inUse: true,
      protoTone: "ok",
      badge: { text: "Connected", tone: "ok", glyph: "dot" },
      state: { label: "Connected now", tone: "ok", glyph: "dot" },
      removeBlocked: true,
      removeNote: "Disconnect Xray first"
    });
    const starting = presentProfileCard(fra, { selectedId: "fra", session: { phase: "connecting", profileId: "fra" } });
    expect(starting).toMatchObject({ inUse: false, badge: { text: "Connecting…", glyph: "spinner" }, removeBlocked: true, removeNote: "Disconnect Xray first" });
    // Another profile's session doesn't block this one.
    expect(presentProfileCard(fra, { session: { phase: "connected", profileId: "ams" } })).toMatchObject({ removeBlocked: false, removeNote: undefined });
    expect(removeBlockedCopy(fra, { phase: "connected", profileId: "fra" }).message).toBe(
      "de-fra-reality is carrying your traffic right now. Disconnect on Connect, then remove it."
    );
  });

  it("explains unsupported and gone profiles, and brackets IPv6 hosts", () => {
    const view = presentProfileCard(lab, {});
    expect(view).toMatchObject({ security: "?", securityBad: true, hint: "Can’t be used for Connect", hitLabel: "lab-unknown can’t be used: Xray doesn’t recognize its settings" });
    expect(view.unsupported?.label).toBe("Unsupported security — can’t connect");
    expect(presentProfileCard(profile({ transport: "unknown" }), {}).unsupported?.label).toBe("Unsupported transport — can’t connect");
    expect(unsupportedSelectCopy(lab).title).toBe("Can’t use lab-unknown");
    expect(presentProfileCard(gone, {}).goneText).toBe("It dropped out of the public list at a refresh. It stays here until you remove it.");
    expect(presentProfileCard({ ...gone, isPinned: true }, {}).goneText).toMatch(/^It dropped out of the public list\. Pinned/u);
    expect(presentProfileCard(v6, {}).address).toBe("[2001:db8::1]:443");
    expect(presentProfileCard(hel, {})).toMatchObject({
      address: "hel.example.net:443,20000-30000",
      protocol: "Hysteria 2",
      transport: "quic",
      security: "tls",
      transportBad: false,
      unsupported: undefined,
      hitTitle: "fi-hel-hy2 · hel.example.net:443,20000-30000"
    });
    expect(presentProfileCard(hy, {}).address).toBe("[2001:db8::7]:8443");
    expect(presentProfileCard(profile({ transport: "hysteria", security: "tls" }), {}).transport).toBe("hysteria");
    expect(presentProfileCard(fra, {})).toMatchObject({ pinLabel: "Pinned", pinTitle: "Pinned: kept when you remove unpinned profiles. Click to unpin." });
  });

  it("tags a Hysteria 2 profile whose link asks to skip certificate checks without a pin, but still lets it be picked", () => {
    const view = presentProfileCard({ ...hel, insecureWithoutPin: true }, {});
    expect(HYSTERIA2_INSECURE_PROFILE_WARNING).toBe(
      "This profile’s link asks to skip certificate checks (insecure=1), which the bundled Xray can’t do, so the server’s certificate is checked as usual. If the server uses a self-signed certificate, add the link again with its pinSHA256 and remove this one."
    );
    expect(view.insecure).toEqual({ tag: "insecure=1", text: HYSTERIA2_INSECURE_PROFILE_WARNING });
    expect(view).toMatchObject({
      unsupported: undefined,
      securityBad: false,
      hint: "Select for Connect",
      hitLabel: "Select fi-hel-hy2 for Connect",
      hitTitle: `fi-hel-hy2 · hel.example.net:443,20000-30000\n${HYSTERIA2_INSECURE_PROFILE_WARNING}`
    });
    expect(presentProfileCard(hel, {}).insecure).toBeUndefined();
    expect(presentProfileCard({ ...hel, insecureWithoutPin: true }, { selectedId: "hel" }).state?.label).toBe("Selected for Connect");
  });

  it("lets a pinned link for the selected insecure=1 profile's server take over its selection", () => {
    const link = (uri: string): LinkPreview => {
      const result = previewShareLink(uri);
      if (result.status !== "ok") {
        throw new Error(`expected ${uri} to read`);
      }
      return result.link;
    };
    const pin = "ab".repeat(32);
    const tagged = { ...hel, insecureWithoutPin: true };
    const library = store([fra, tagged], "hel");
    const pinned = link(`hy2://letmein@hel.example.net:20000-30000,443?pinSHA256=${pin}#fi-hel-hy2`);
    expect(pinned.certificatePinned).toBe(true);
    expect(insecureProfileFixedBy(pinned, library)).toBe(tagged);
    // Same host, other ports; no pin; another host; not the selected profile; not tagged.
    expect(insecureProfileFixedBy(link(`hy2://letmein@hel.example.net:443?pinSHA256=${pin}`), library)).toBeUndefined();
    expect(insecureProfileFixedBy(link("hy2://letmein@hel.example.net:443,20000-30000#fixed"), library)).toBeUndefined();
    expect(insecureProfileFixedBy(link(`hy2://letmein@other.example.net:443,20000-30000?pinSHA256=${pin}`), library)).toBeUndefined();
    expect(insecureProfileFixedBy(pinned, store([fra, tagged], "fra"))).toBeUndefined();
    expect(insecureProfileFixedBy(pinned, store([fra, hel], "hel"))).toBeUndefined();
    expect(insecureProfileFixedBy(undefined, library)).toBeUndefined();
    // Without hopping the single port has to match.
    const single = { ...hy, insecureWithoutPin: true };
    expect(insecureProfileFixedBy(link(`hy2://pw@[2001:db8::7]:8443?pinSHA256=${pin}`), store([single], "hy"))).toBe(single);
    expect(insecureProfileFixedBy(link(`hy2://pw@[2001:db8::7]:443?pinSHA256=${pin}`), store([single], "hy"))).toBeUndefined();

    expect(fixedInsecureCopy(tagged)).toBe("Saving selects it for Connect in place of fi-hel-hy2, which is tagged insecure=1.");
    expect(fixedInsecureCopy(tagged, { name: "fi-hel-pinned" })).toBe(
      "fi-hel-pinned is selected for Connect in place of fi-hel-hy2, which is tagged insecure=1. You can remove that one now."
    );
    expect(fixedInsecureCopy(tagged, { name: "fi-hel-hy2" })).toBe(
      "The fi-hel-hy2 with the pinSHA256 is selected for Connect in place of the one tagged insecure=1. You can remove that one now."
    );
  });

  it("finds tagged profiles by the insecure=1 tag", () => {
    const tagged = { ...hy, insecureWithoutPin: true };
    expect(filterProfiles([fra, hel, tagged], "all", "insecure").map((item) => item.id)).toEqual(["hy"]);
    expect(filterProfiles([fra, hel, tagged], "all", "insecure=1").map((item) => item.id)).toEqual(["hy"]);
  });
});

describe("results bar and paging", () => {
  const counts = { all: 128, pinned: 12, gone: 6, goneUnpinned: 5, unpinned: 116 };

  it("summarises what the grid shows", () => {
    expect(resultsSummary({ filter: "all", query: "", matches: 128, shown: 100, counts })).toEqual({ text: "Showing 100 of 128", sub: "In the order you added them" });
    expect(resultsSummary({ filter: "all", query: "", matches: 128, shown: 128, counts }).text).toBe("All 128 profiles");
    expect(resultsSummary({ filter: "pinned", query: "", matches: 12, shown: 12, counts })).toEqual({ text: "12 pinned", sub: "Kept when you remove unpinned profiles" });
    expect(resultsSummary({ filter: "gone", query: " tokyo ", matches: 1, shown: 1, counts })).toEqual({ text: "1 match for “tokyo”", sub: "In Gone from source" });
    expect(noMatchCopy("pinned", "zzz").text).toMatch(/^Nothing in Pinned matches\./u);
  });

  it("labels Show more", () => {
    expect(moreBlockCopy(100, 128)).toEqual({ meta: "Showing 100 of 128", label: "Show 28 more", percent: 78 });
    expect(moreBlockCopy(100, 350).label).toBe("Show 100 more · 250 left");
  });

  it("says which profile Connect uses", () => {
    expect(currentSelection([fra, ams], "fra", undefined)).toEqual({ label: "Connect uses", name: "de-fra-reality" });
    expect(currentSelection([fra, ams], "fra", { phase: "connected", profileId: "ams" })).toEqual({ label: "Next connect uses", name: "de-fra-reality" });
    expect(currentSelection([fra], undefined, undefined)).toEqual({ label: "No profile selected" });
  });
});

describe("public list", () => {
  const now = new Date(2026, 9, 6, 12, 30);
  const listed = profile({ id: "q1", source: "remote", lastSeenAt: new Date(2026, 9, 6, 11, 40).toISOString() });

  it("describes the last refresh", () => {
    const info = publicListInfo([fra, listed, gone]);
    expect(info.listed).toBe(1);
    expect(publicListMeta({ info, refreshing: false, now })).toEqual({ text: "Last refreshed today 11:40 · 1 profile in the list", error: false });
    expect(publicListMeta({ info, refreshing: true, now }).text).toBe("Downloading the public list…");
    expect(publicListMeta({ info, refreshing: false, now, failure: { at: new Date(2026, 9, 6, 12, 6), reason: "the source timed out" } })).toEqual({
      text: "Refresh failed at 12:06: the source timed out. Last good list from today 11:40.",
      error: true
    });
    expect(publicListMeta({ info: publicListInfo([fra]), refreshing: false, now }).text).toMatch(/^Not loaded yet\./u);
  });

  it("prefers the stored refresh record, which survives removing the public profiles", () => {
    const refresh = { at: new Date(2026, 9, 6, 9, 15).toISOString(), listed: 96 };
    expect(publicListInfo([], refresh)).toEqual({ lastRefreshAt: refresh.at, listed: 96 });
    expect(publicListMeta({ info: publicListInfo([fra, listed], refresh), refreshing: false, now }).text).toBe(
      "Last refreshed today 09:15 · 96 profiles in the list"
    );
  });

  it("explains refresh failures", () => {
    expect(describeRefreshFailure(new Error("Error invoking remote method 'shadow-ssh:refresh-proxy-profiles': Error: Public proxy refresh timed out."))).toMatchObject({
      reason: "the source timed out",
      message: "The source didn’t answer within 30 seconds. Nothing changed. Check your connection and try again."
    });
    expect(describeRefreshFailure(new Error("Public proxy refresh failed: 404 Not Found")).reason).toBe("the source answered 404 Not Found");
    expect(describeRefreshFailure(new Error("Remote proxy source is larger than the allowed limit.")).reason).toBe("the list was over 2 MB");
    expect(describeRefreshFailure(new Error("Proxy profile count exceeds the 10000 profile limit.")).reason).toBe("it would pass the 10,000-profile limit");
    const offline = describeRefreshFailure(new Error("getaddrinfo ENOTFOUND gitverse.ru"));
    expect(offline.reason).toBe("the source couldn’t be reached");
    expect(offline.message).toMatch(/Nothing changed\.$/u);
  });

  it("summarises a refresh from the library before and after", () => {
    const first = summarizeRefresh(store([]), store([listed], "q1"), { imported: 96, updated: 0, skipped: 0, failed: 0, errors: [] });
    expect(first).toEqual({ tone: "success", title: "Public list loaded", message: "96 new profiles. de-fra-reality is selected for Connect." });

    const same = summarizeRefresh(store([fra, listed], "fra"), store([fra, listed], "fra"), { imported: 0, updated: 95, skipped: 0, failed: 0, errors: [] });
    expect(same).toEqual({ tone: "success", title: "Public list refreshed", message: "No changes: 95 updated, nothing new, nothing gone from source." });

    const goneNow = { ...listed, isStale: true };
    const moved = summarizeRefresh(store([fra, listed], "q1"), store([fra, goneNow, profile({ id: "n1" })], "fra"), { imported: 2, updated: 93, skipped: 0, failed: 0, errors: [] });
    expect(moved).toEqual({
      tone: "success",
      title: "Public list refreshed: 2 new, 93 updated, 1 gone from source",
      message: "Gone profiles stay until you remove them. Connect now uses de-fra-reality."
    });

    const empty = summarizeRefresh(store([fra, listed], "fra"), store([fra, goneNow], "fra"), { imported: 0, updated: 0, skipped: 3, failed: 0, errors: [] });
    expect(empty.tone).toBe("warning");
    expect(empty.message).toBe("None of its lines were usable links, so 1 public profile is now gone from source. They stay until you remove them.");
  });
});

describe("saving and removing", () => {
  it("tells added from updated profiles", () => {
    const added = profile({ id: "new", name: "pl-waw-xhttp" });
    expect(savedProfileCopy(store([]), store([added], "new"))).toEqual({ title: "Profile saved", message: "pl-waw-xhttp is in Xray profiles. It’s selected for Connect." });
    expect(savedProfileCopy(store([fra], "fra"), store([fra, added], "fra")).message).toBe("pl-waw-xhttp is in Xray profiles.");
    const touched = { ...ams, updatedAt: "2026-10-06T12:00:00.000Z" };
    expect(savedProfileCopy(store([fra, ams]), store([fra, touched]))).toEqual({ title: "Profile updated", message: "nl-ams-ws was already in your library, so its details were updated." });
  });

  it("states counts and what happens to a running tunnel", () => {
    const counts = { all: 128, pinned: 12, gone: 6, goneUnpinned: 5, unpinned: 116 };
    const running = bulkRemoveCopy({ counts, session: { phase: "connected", profileId: "fra" }, sessionProfile: fra });
    expect(running).toMatchObject({
      title: "Remove 116 unpinned profiles?",
      description: "Your 12 pinned profiles stay. This can’t be undone.",
      confirmLabel: "Remove 116 profiles",
      removedHint: "including 5 gone from source",
      xrayWarning: "The tunnel through de-fra-reality closes before anything is removed, even though that profile is pinned. Connect again when it’s done."
    });
    expect(bulkRemoveCopy({ counts, session: { phase: "connected", profileId: "ams" }, sessionProfile: ams }).xrayWarning).toBe(
      "The tunnel through nl-ams-ws closes first, and nl-ams-ws is removed with the other unpinned profiles. Pick another profile on Connect when it’s done."
    );
    expect(bulkRemoveCopy({ counts, sshSessionName: "Frankfurt-01" }).calmNote).toBe(
      "Xray isn’t running, so your SSH session to Frankfurt-01 stays up. When Xray is connected, it disconnects before profiles are removed."
    );
    expect(bulkRemoveCopy({ counts: { ...counts, goneUnpinned: 0 } })).toMatchObject({ removedHint: "unpinned profiles", xrayWarning: undefined });
    expect(bulkRemoveCopy({ counts: { all: 3, pinned: 0, gone: 0, goneUnpinned: 0, unpinned: 3 } }).description).toBe("Nothing is pinned, so every profile goes. This can’t be undone.");
    expect(removedUnpinnedCopy(3, 0, false).message).toBe("Nothing was pinned, so your library is empty now.");
    expect(removedUnpinnedCopy(116, 12, true)).toEqual({
      title: "Removed 116 unpinned profiles",
      message: "12 pinned profiles kept. Xray was disconnected first. Connect again when you are ready."
    });
  });

  it("names the profile being removed and where the selection goes", () => {
    expect(singleRemoveCopy(gone)).toMatchObject({ title: "Remove “public-23”?", meta: "45.12.33.1:8443 · Public", footnote: "If it’s still in the public list, the next refresh brings it back." });
    expect(singleRemoveCopy(ams).footnote).toBe("To get it back, add its link again. Copy it first with ⋯ → Copy link if you might need it.");
    expect(singleRemoveCopy(hel).meta).toBe("hel.example.net:443,20000-30000 · Imported");
    expect(removedOneCopy(fra, store([fra, ams], "fra"), store([ams], "ams"))).toEqual({
      title: "Profile removed",
      message: "de-fra-reality is no longer in your library. Connect now uses nl-ams-ws."
    });
  });
});

describe("renaming and copying links", () => {
  it("names the card's action menu after the profile", () => {
    expect(presentProfileCard(ams, {})).toMatchObject({ moreLabel: "More actions for nl-ams-ws", menuLabel: "Actions for nl-ams-ws", removeBlocked: false });
    expect(renameFailedTitle(ams)).toBe("Couldn’t rename nl-ams-ws");
    expect(renamedNotice("Amsterdam · WS")).toBe("Renamed to Amsterdam · WS.");
  });

  it("warns that a copied link carries credentials, except for public profiles", () => {
    expect(copiedLinkCopy(ams)).toEqual({
      title: "Link copied",
      message: "Anyone with the link to nl-ams-ws can connect through it, so share it only with people you trust. Your clipboard isn’t cleared automatically."
    });
    expect(copiedLinkCopy(fra).message).toMatch(/^Anyone with the link to de-fra-reality/u);
    expect(copiedLinkCopy(gone)).toEqual({ title: "Link copied", message: "public-23 is from the public list." });
  });

  it("explains a link that can't be decrypted and keeps the raw error for details", () => {
    const decrypt = new Error("Error invoking remote method 'shadow-ssh:copy-proxy-profile-link': Error: Error while decrypting the ciphertext provided to safeStorage.decryptString.");
    expect(copyLinkFailedCopy(decrypt)).toEqual({
      title: "Couldn’t copy the link",
      message: "Saved links can’t be read after the app folder moves to another PC or the system keychain is reset. Add the link again to replace this profile.",
      details: decrypt.message
    });
    expect(copyLinkFailedCopy(new Error("Secret record is missing.")).message).toMatch(/^Saved links can’t be read/u);
    expect(copyLinkFailedCopy(new Error("Invalid encrypted secret payload.")).message).toMatch(/^Saved links can’t be read/u);
    const missing = new Error("Error invoking remote method 'shadow-ssh:copy-proxy-profile-link': Error: Proxy profile does not exist.");
    expect(copyLinkFailedCopy(missing)).toEqual({ title: "Couldn’t copy the link", message: "Proxy profile does not exist.", details: missing.message });
  });
});
