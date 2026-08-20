package dataplane

import (
	"net/netip"
	"testing"

	"shadowssh/service/internal/routing"
)

func processRule(id string, value string) routing.Rule {
	return routing.Rule{ID: id, Type: routing.RuleProcessName, Value: value, Enabled: true}
}

func domainRule(id string, value string) routing.Rule {
	return routing.Rule{ID: id, Type: routing.RuleDomain, Value: value, Enabled: true}
}

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	parsed, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func TestProcessRuleBeatsDirectList(t *testing.T) {
	// The direct list must not carve holes in a selected application's
	// traffic: this is the ordering local-routing-enforcement.ts documents.
	policy := NewPolicy(Config{
		Mode:          routing.ModeSelectedRules,
		Rules:         []routing.Rule{processRule("r1", "discord.exe")},
		DirectDomains: []string{"discord.com"},
		UDPSupported:  true,
	})

	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "162.159.128.233:443"),
		Domains:     []string{"gateway.discord.com"},
		ProcessName: "Discord.exe",
	})
	if decision.Verdict != VerdictProxy || decision.Reason != "process.name" {
		t.Fatalf("expected the process rule to win, got %+v", decision)
	}
	if decision.RuleID != "r1" {
		t.Fatalf("expected rule r1, got %q", decision.RuleID)
	}
}

func TestDirectListAppliesToUnselectedProcess(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:          routing.ModeSelectedRules,
		Rules:         []routing.Rule{processRule("r1", "discord.exe")},
		DirectDomains: []string{"bank.example"},
		ProxyDomains:  []string{"example"},
		UDPSupported:  true,
	})

	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "203.0.113.7:443"),
		Domains:     []string{"login.bank.example"},
		ProcessName: "chrome.exe",
	})
	// The proxy list is consulted before the direct list, exactly as on the
	// system-proxy path, so a broader proxy entry wins over a narrower direct
	// one.
	if decision.Verdict != VerdictProxy || decision.Reason != "proxy-list" {
		t.Fatalf("expected the proxy list to win, got %+v", decision)
	}
}

func TestProtectedEndpointIsNeverTunnelled(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:               routing.ModeProxyAll,
		ProtectedEndpoints: []netip.AddrPort{mustAddrPort(t, "198.51.100.4:22")},
		UDPSupported:       true,
	})

	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "198.51.100.4:22"),
		ProcessName: "shadow-ssh.exe",
	})
	if decision.Verdict != VerdictDirect || decision.Reason != "protected-ssh-connection" {
		t.Fatalf("expected the transport's own endpoint to stay direct, got %+v", decision)
	}

	// A different port on the same host is ordinary traffic.
	other := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "198.51.100.4:443")})
	if other.Verdict != VerdictProxy {
		t.Fatalf("expected other ports to be routed normally, got %+v", other)
	}
}

func TestSelectedProcessUDPIsDroppedWhenTheTransportCannotCarryIt(t *testing.T) {
	// Letting it out directly would leak exactly the traffic the rule exists to
	// capture; dropping it makes QUIC fall back to TCP, which is tunnelled.
	policy := NewPolicy(Config{
		Mode:         routing.ModeSelectedRules,
		Rules:        []routing.Rule{processRule("r1", "discord.exe")},
		UDPSupported: false,
	})

	selected := policy.Decide(Flow{
		Protocol:    ProtocolUDP,
		Destination: mustAddrPort(t, "162.159.128.233:50000"),
		ProcessName: "discord.exe",
	})
	if selected.Verdict != VerdictDrop || selected.Reason != "udp-not-supported" {
		t.Fatalf("expected a selected process's UDP to be dropped, got %+v", selected)
	}

	unselected := policy.Decide(Flow{
		Protocol:    ProtocolUDP,
		Destination: mustAddrPort(t, "162.159.128.233:50000"),
		ProcessName: "chrome.exe",
	})
	if unselected.Verdict != VerdictDirect {
		t.Fatalf("expected an unselected process's UDP to stay direct, got %+v", unselected)
	}
}

func TestSelectedProcessUDPIsTunnelledWhenTheTransportCanCarryIt(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:         routing.ModeSelectedRules,
		Rules:        []routing.Rule{processRule("r1", "discord.exe")},
		UDPSupported: true,
	})

	decision := policy.Decide(Flow{
		Protocol:    ProtocolUDP,
		Destination: mustAddrPort(t, "162.159.128.233:50000"),
		ProcessName: "discord.exe",
	})
	if decision.Verdict != VerdictProxy {
		t.Fatalf("expected UDP to be tunnelled on a transport that carries it, got %+v", decision)
	}
}

func TestProcessNameIsMatchedOnTheBareFileName(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{processRule("r1", "Telegram.exe")},
	})

	for _, name := range []string{"telegram.exe", `C:\Users\x\AppData\Roaming\Telegram Desktop\Telegram.exe`, "TELEGRAM.EXE"} {
		decision := policy.Decide(Flow{
			Protocol:    ProtocolTCP,
			Destination: mustAddrPort(t, "149.154.167.51:443"),
			ProcessName: name,
		})
		if decision.Verdict != VerdictProxy {
			t.Fatalf("expected %q to match the rule, got %+v", name, decision)
		}
	}
}

func TestUnattributedFlowFallsBackToDomainAndIPRules(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{processRule("r1", "discord.exe"), domainRule("r2", "example.com")},
	})

	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "93.184.216.34:443"),
		Domains:     []string{"www.example.com"},
	})
	if decision.Verdict != VerdictProxy || decision.Reason != "domain" {
		t.Fatalf("expected the domain rule to match without attribution, got %+v", decision)
	}

	unmatched := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "93.184.216.34:443")})
	if unmatched.Verdict != VerdictDirect {
		t.Fatalf("expected an unmatched flow to stay direct, got %+v", unmatched)
	}
}

func TestProxyAllRoutesEverythingButTheTransport(t *testing.T) {
	policy := NewPolicy(Config{Mode: routing.ModeProxyAll, UDPSupported: true})
	decision := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "1.1.1.1:443")})
	if decision.Verdict != VerdictProxy || decision.Reason != "proxy-all" {
		t.Fatalf("expected proxy-all to route everything, got %+v", decision)
	}
}

func TestProcessRuleWithoutAnExtensionStillMatches(t *testing.T) {
	// The UI accepts a bare name, and normalizeWindowsProcessName appends
	// `.exe` before comparing. A dataplane that skipped that step left such a
	// rule silently inert - which is a leak, not a no-op.
	policy := NewPolicy(Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{processRule("r1", "discord")},
	})
	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "162.159.128.233:443"),
		ProcessName: "Discord.exe",
	})
	if decision.Verdict != VerdictProxy || decision.Reason != "process.name" {
		t.Fatalf("expected a bare rule name to match, got %+v", decision)
	}
}

func TestProcessRuleValuesTheUIWouldRejectDoNotMatch(t *testing.T) {
	// validateProcessName refuses a path, so a rule holding one cannot exist in
	// the UI. Honouring it here would make the two paths disagree about which
	// applications are selected.
	policy := NewPolicy(Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{processRule("r1", `C:\Apps\Discord.exe`), domainRule("r2", "example.com")},
	})
	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "162.159.128.233:443"),
		ProcessName: "discord.exe",
	})
	if decision.Verdict != VerdictDirect {
		t.Fatalf("expected a path-shaped rule to be ignored, got %+v", decision)
	}
}

func TestAnAliasLearnedFromACnameChainStillMatchesTheQueriedName(t *testing.T) {
	// A CNAME answers under the alias. Matching only the record owner would
	// miss every rule written against the name the user actually types.
	policy := NewPolicy(Config{
		Mode:          routing.ModeSelectedRules,
		Rules:         []routing.Rule{domainRule("r1", "discord.com")},
		DirectDomains: []string{"cdn.example.net"},
	})
	decision := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "162.159.128.233:443"),
		Domains:     []string{"gateway.discord.com", "cdn.example.net"},
	})
	if decision.Verdict != VerdictProxy || decision.Reason != "domain" {
		t.Fatalf("expected the queried name to match the rule, got %+v", decision)
	}
}
