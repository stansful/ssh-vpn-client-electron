package routing

import "testing"

func TestMatcherSelectedRules(t *testing.T) {
	matcher := NewMatcher(ModeSelectedRules, []Rule{
		{ID: "domain-root", Type: RuleDomain, Value: "example.com", Enabled: true},
		{ID: "domain-wild", Type: RuleDomain, Value: "*.internal.test", Enabled: true},
		{ID: "v6", Type: RuleIP, Value: "2001:db8::/32", Enabled: true},
		{ID: "proc", Type: RuleProcessName, Value: "Chrome.EXE", Enabled: true},
		{ID: "bad", Type: RuleIP, Value: "not-an-ip", Enabled: true},
	})

	assertDecision(t, matcher.Decide(Descriptor{DestinationDomain: "example.com"}), true, "domain", "domain-root")
	assertDecision(t, matcher.Decide(Descriptor{DestinationDomain: "api.internal.test"}), true, "domain", "domain-wild")
	assertDecision(t, matcher.Decide(Descriptor{DestinationDomain: "internal.test"}), false, "no-match", "")
	assertDecision(t, matcher.Decide(Descriptor{DestinationIP: "2001:db8::42"}), true, "ip", "v6")
	assertDecision(t, matcher.Decide(Descriptor{ProcessName: "chrome.exe"}), true, "process.name", "proc")

	summary := matcher.Summary()
	if summary.InvalidRules != 1 {
		t.Fatalf("expected one invalid rule, got %d", summary.InvalidRules)
	}
}

func TestMatcherProxyAllAndUDPTCPOnly(t *testing.T) {
	matcher := NewMatcher(ModeProxyAll, nil)
	tcp := matcher.Decide(Descriptor{Protocol: "tcp"})
	if !tcp.ShouldProxy || tcp.Reason != "proxy-all" {
		t.Fatalf("expected proxy-all tcp decision, got %+v", tcp)
	}

	udp := matcher.Decide(Descriptor{Protocol: "udp"})
	if udp.ShouldProxy || udp.BlockedReason != "udp-not-supported" {
		t.Fatalf("expected UDP to be blocked, got %+v", udp)
	}
}

func TestMatcherRejectsMalformedSelectedTargets(t *testing.T) {
	matcher := NewMatcher(ModeSelectedRules, []Rule{
		{ID: "domain", Type: RuleDomain, Value: "bad domain", Enabled: true},
		{ID: "process", Type: RuleProcessName, Value: `C:\\browser.exe`, Enabled: true},
		{ID: "unknown", Type: RuleType("unknown"), Value: "example.com", Enabled: true},
	})
	summary := matcher.Summary()
	if summary.EnabledRules != 0 || summary.InvalidRules != 3 {
		t.Fatalf("malformed targets were compiled: %+v", summary)
	}
}

func TestValidProxyDomainAcceptsSuffixesAndRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{".ru", "example.com", "*.example.com"} {
		if !ValidProxyDomain(value) {
			t.Fatalf("valid proxy domain %q was rejected", value)
		}
	}
	for _, value := range []string{"", ".", "bad domain", "-bad.example"} {
		if ValidProxyDomain(value) {
			t.Fatalf("invalid proxy domain %q was accepted", value)
		}
	}
}

func assertDecision(t *testing.T, decision Decision, shouldProxy bool, reason string, ruleID string) {
	t.Helper()
	if decision.ShouldProxy != shouldProxy || decision.Reason != reason || decision.RuleID != ruleID {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}
