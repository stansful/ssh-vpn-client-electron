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

func TestDirectListBeatsTheProxyListForAnUnselectedProcess(t *testing.T) {
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
	// The direct list is consulted before the proxy list, as on every other
	// path, so a narrower direct entry wins over a broader proxy one.
	if decision.Verdict != VerdictDirect || decision.Reason != "direct-list" {
		t.Fatalf("expected the direct list to win, got %+v", decision)
	}
	// A site only the proxy list names is still tunnelled.
	other := policy.Decide(Flow{
		Protocol:    ProtocolTCP,
		Destination: mustAddrPort(t, "203.0.113.8:443"),
		Domains:     []string{"shop.example"},
		ProcessName: "chrome.exe",
	})
	if other.Verdict != VerdictProxy || other.Reason != "proxy-list" {
		t.Fatalf("expected the proxy list to select the site, got %+v", other)
	}
}

// TestPolicyAppliesTheSharedRoutingOrder walks the eight steps every routing
// path applies, each case set up so the step under test is the first that
// can answer and the steps after it would answer differently.
func TestPolicyAppliesTheSharedRoutingOrder(t *testing.T) {
	protected := mustAddrPort(t, "198.51.100.4:443")
	rules := []routing.Rule{
		processRule("proc", "selected.exe"),
		domainRule("dom", "ru-rule.example"),
		{ID: "net", Type: routing.RuleIP, Value: "203.0.113.0/24", Enabled: true},
		// Rules for the network behind the server: an explicit rule wins over
		// the local network (step 2 before step 3).
		{ID: "lan", Type: routing.RuleIP, Value: "10.0.0.0/8", Enabled: true},
		domainRule("corp", "corp.local"),
	}
	build := func(mode routing.Mode) *Policy {
		return NewPolicy(Config{
			Mode:               mode,
			Rules:              rules,
			ProxyDomains:       []string{"blocked.example", ".example"},
			DirectDomains:      []string{"ru-rule.example", "yandex.example", "ru-site.example"},
			ProtectedEndpoints: []netip.AddrPort{protected},
			DirectProcesses:    []ProcessIdentity{{PID: 4242, Name: "xray"}},
			UDPSupported:       true,
		})
	}
	cases := []struct {
		name    string
		mode    routing.Mode
		flow    Flow
		verdict Verdict
		reason  string
	}{
		{"1 the transport beats a process rule", routing.ModeProxyAll,
			Flow{Destination: protected, ProcessName: "selected.exe"}, VerdictDirect, "protected-ssh-connection"},
		{"1.5 the transport's process beats proxy-all", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.80:443"), ProcessName: `C:\Shadow\XRAY.EXE`, ProcessID: 4242}, VerdictDirect, "direct-process"},
		{"1.5 the transport's process beats an address rule", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "203.0.113.9:443"), ProcessName: "xray.exe", ProcessID: 4242}, VerdictDirect, "direct-process"},
		{"1.5 the transport's process beats a rule for the local network", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "10.1.2.3:445"), ProcessName: "xray.exe", ProcessID: 4242}, VerdictDirect, "direct-process"},
		{"1.5 another program called xray.exe is routed like any other", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.80:443"), ProcessName: `C:\v2rayN\bin\Xray\XRAY.EXE`, ProcessID: 777}, VerdictProxy, "proxy-all"},
		{"1.5 the transport's ID under another program's name is not the transport", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "203.0.113.9:443"), ProcessName: "other.exe", ProcessID: 4242}, VerdictProxy, "ip"},
		{"2 an address rule for a private range beats the local network", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "10.1.2.3:445")}, VerdictProxy, "ip"},
		{"2 an address rule for a private range wins in full tunnel too", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "10.1.2.3:445"), ProcessName: "other.exe"}, VerdictProxy, "ip"},
		{"2 a domain rule for a .local name beats the local network", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "192.168.1.20:443"), Domains: []string{"wiki.corp.local"}, NameSniffed: true}, VerdictProxy, "domain"},
		{"2 a domain rule beats the direct list", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"www.ru-rule.example"}}, VerdictProxy, "domain"},
		{"2 an address rule beats the direct list", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "203.0.113.9:443"), Domains: []string{"yandex.example"}}, VerdictProxy, "ip"},
		{"3 a private address no rule names beats a process rule", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "172.16.5.5:445"), ProcessName: "selected.exe"}, VerdictDirect, "local-destination"},
		{"3 a private address no rule names stays direct", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "192.168.1.1:80")}, VerdictDirect, "local-destination"},
		{"3 a .local name the flow carried is local", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"nas.local"}, NameSniffed: true}, VerdictDirect, "local-destination"},
		{"4 a process rule beats the direct list", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"yandex.example"}, ProcessName: "Selected"}, VerdictProxy, "process.name"},
		{"5 the direct list beats proxy-all", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"mail.yandex.example"}}, VerdictDirect, "direct-list"},
		{"5 the direct list beats the proxy list", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"ru-site.example"}}, VerdictDirect, "direct-list"},
		{"6 proxy-all takes the rest", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"elsewhere.test"}}, VerdictProxy, "proxy-all"},
		{"6 proxy-all takes an address without a name", routing.ModeProxyAll,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443")}, VerdictProxy, "proxy-all"},
		{"7 the proxy list selects in selected-rules", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"www.blocked.example"}}, VerdictProxy, "proxy-list"},
		{"8 nothing else is direct", routing.ModeSelectedRules,
			Flow{Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"elsewhere.test"}, ProcessName: "other.exe"}, VerdictDirect, "no-match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.flow.Protocol = ProtocolTCP
			decision := build(c.mode).Decide(c.flow)
			if decision.Verdict != c.verdict || decision.Reason != c.reason {
				t.Fatalf("got %+v, want %s/%s", decision, c.verdict, c.reason)
			}
		})
	}
}

// The transport's own process is picked out by its ID: a user's process
// rule for another program that shares the file name - another client's own
// Xray core - still selects that program.
func TestOnlyTheTransportsOwnProcessGoesDirect(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:            routing.ModeSelectedRules,
		Rules:           []routing.Rule{processRule("other-client", "xray.exe")},
		DirectProcesses: []ProcessIdentity{{PID: 4242, Name: "xray.exe"}},
	})
	destination := mustAddrPort(t, "203.0.113.9:443")
	own := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: destination, ProcessName: "xray.exe", ProcessID: 4242})
	if own.Verdict != VerdictDirect || own.Reason != "direct-process" {
		t.Fatalf("the transport's own dial: got %+v", own)
	}
	other := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: destination, ProcessName: "xray.exe", ProcessID: 777})
	if other.Verdict != VerdictProxy || other.Reason != "process.name" || other.RuleID != "other-client" {
		t.Fatalf("another program called xray.exe: got %+v", other)
	}
	unknown := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: destination, ProcessName: "xray.exe"})
	if unknown.Reason == "direct-process" {
		t.Fatalf("an owner whose ID is not known was taken for the transport: %+v", unknown)
	}
}

// TestPrivateDestinationsStayDirectInFullTunnel is also the proof that a
// process rule does not pull the local network into the tunnel: the flows
// below belong to the selected process.
func TestPrivateDestinationsStayDirectInFullTunnel(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:         routing.ModeProxyAll,
		Rules:        []routing.Rule{processRule("p", "selected.exe")},
		UDPSupported: true,
	})
	for _, destination := range []string{
		"127.0.0.1:8080", "127.255.0.9:1",
		"10.0.0.1:445", "10.255.255.254:80",
		"172.16.0.1:443", "172.31.255.254:443",
		"192.168.1.1:80",
		"169.254.10.20:80",
		"100.64.0.1:443", "100.127.255.254:443",
		"0.0.0.1:9",
		"[::1]:8080",
		"[fe80::1]:22",
		"[fd7a:c0de:5417::2]:53", "[fc00::5]:443",
		"[::ffff:10.0.0.1]:445", "[::ffff:192.168.1.1]:80", "[::ffff:127.0.0.1]:8080",
	} {
		for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP} {
			decision := policy.Decide(Flow{Protocol: protocol, Destination: mustAddrPort(t, destination), ProcessName: "selected.exe"})
			if decision.Verdict != VerdictDirect || decision.Reason != "local-destination" {
				t.Fatalf("%s %s: expected local-destination, got %+v", protocol, destination, decision)
			}
		}
	}
	// The edges of each range, and look-alikes, are ordinary traffic.
	for _, destination := range []string{
		"11.0.0.1:443", "172.32.0.1:443", "172.15.255.255:443", "192.169.0.1:443",
		"100.128.0.1:443", "100.63.255.255:443", "1.0.0.1:443",
		"[2001:db8::1]:443", "[fec0::1]:443", "[::ffff:8.8.8.8]:443",
	} {
		decision := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, destination)})
		if decision.Verdict != VerdictProxy {
			t.Fatalf("%s: expected proxy-all, got %+v", destination, decision)
		}
	}
	// Names that can only mean the local network, when the flow named them.
	for _, name := range []string{"localhost", "printer", "nas.local", "NAS.Local."} {
		decision := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{name}, NameSniffed: true})
		if decision.Verdict != VerdictDirect || decision.Reason != "local-destination" {
			t.Fatalf("%q: expected local-destination, got %+v", name, decision)
		}
	}
}

func TestAUserRuleTunnelsTheNetworkBehindTheServer(t *testing.T) {
	// 10.0.0.0/8 is how a user reaches the server's own private network; it
	// was the rules form's example before the local network went direct.
	lan := routing.Rule{ID: "lan", Type: routing.RuleIP, Value: "10.0.0.0/8", Enabled: true}
	target := mustAddrPort(t, "10.1.2.3:445")
	for _, mode := range []routing.Mode{routing.ModeSelectedRules, routing.ModeProxyAll} {
		withRule := NewPolicy(Config{Mode: mode, Rules: []routing.Rule{lan, processRule("p", "selected.exe")}, UDPSupported: true})
		for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP} {
			decision := withRule.Decide(Flow{Protocol: protocol, Destination: target, ProcessName: "other.exe"})
			if decision.Verdict != VerdictProxy || decision.Reason != "ip" || decision.RuleID != "lan" {
				t.Fatalf("%s %s: expected the rule to tunnel 10.1.2.3, got %+v", mode, protocol, decision)
			}
		}
		// Without the rule the same address stays on the local network, for
		// the selected process too.
		without := NewPolicy(Config{Mode: mode, Rules: []routing.Rule{processRule("p", "selected.exe")}, UDPSupported: true})
		if decision := without.Decide(Flow{Protocol: ProtocolTCP, Destination: target, ProcessName: "selected.exe"}); decision.Verdict != VerdictDirect || decision.Reason != "local-destination" {
			t.Fatalf("%s: expected 10.1.2.3 to stay direct without a rule, got %+v", mode, decision)
		}
	}
	// A selected flow the transport cannot carry is refused, not leaked.
	ssh := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{lan}})
	if decision := ssh.Decide(Flow{Protocol: ProtocolUDP, Destination: target}); decision.Verdict != VerdictDrop {
		t.Fatalf("expected selected UDP on a TCP-only transport to be dropped, got %+v", decision)
	}
	// A rule that only partly covers the local network selects that part.
	wide := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{{ID: "all", Type: routing.RuleIP, Value: "0.0.0.0/0", Enabled: true}}})
	if decision := wide.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.168.1.1:80")}); decision.Verdict != VerdictProxy {
		t.Fatalf("expected 0.0.0.0/0 to cover a private address, got %+v", decision)
	}
}

func TestALearnedNameAUserRuleNamesSelectsAPrivateAddress(t *testing.T) {
	// Split-horizon DNS answered wiki.corp.example with a private address. Any
	// learned name may select a flow, as on every other step that selects;
	// only releasing one takes the flow's own name.
	policy := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{domainRule("d", "corp.example")}})
	flow := Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "10.20.0.5:22"), Domains: []string{"wiki.corp.example"}}
	if decision := policy.Decide(flow); decision.Verdict != VerdictProxy || decision.Reason != "domain" {
		t.Fatalf("expected the domain rule to tunnel the private address, got %+v", decision)
	}
	flow.Domains = []string{"printer.example"}
	if decision := policy.Decide(flow); decision.Verdict != VerdictDirect || decision.Reason != "local-destination" {
		t.Fatalf("expected an unnamed private address to stay direct, got %+v", decision)
	}
}

func TestALearnedLocalNameDoesNotPullAPublicAddressOutOfTheTunnel(t *testing.T) {
	// A resolver answers www.youtube.com with "CNAME edge.local" and a public
	// address. Every flow to that address is then known by edge.local too;
	// taking that for the local network would send a selected application's
	// traffic - and in full tunnel everyone's - out directly.
	cache := NewDomainCache(0)
	cache.Record(parseDNSAnswers(buildResponseWithOwner("www.youtube.com", "edge.local", netip.MustParseAddr("142.250.74.14"))))
	destination := mustAddrPort(t, "142.250.74.14:443")
	domains := cache.Lookup(destination.Addr())
	if len(domains) != 2 {
		t.Fatalf("expected both names to be learned, got %v", domains)
	}

	selected := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{processRule("p", "chrome.exe")}})
	if decision := selected.Decide(Flow{Protocol: ProtocolTCP, Destination: destination, Domains: domains, ProcessName: "chrome.exe"}); decision.Verdict != VerdictProxy || decision.Reason != "process.name" {
		t.Fatalf("expected the process rule to keep the flow in the tunnel, got %+v", decision)
	}
	full := NewPolicy(Config{Mode: routing.ModeProxyAll})
	if decision := full.Decide(Flow{Protocol: ProtocolTCP, Destination: destination, Domains: domains}); decision.Verdict != VerdictProxy {
		t.Fatalf("expected full tunnel to keep the flow, got %+v", decision)
	}
}

func TestTheDirectListReleasesALearnedFlowOnlyWhenItCoversEveryName(t *testing.T) {
	// One address remembered under a blocked site and a Russian one: a flow
	// with no name of its own could be for either, and the tunnel is the side
	// to err on.
	shared := mustAddrPort(t, "192.0.2.10:443")
	for _, mode := range []routing.Mode{routing.ModeSelectedRules, routing.ModeProxyAll} {
		policy := NewPolicy(Config{
			Mode:          mode,
			ProxyDomains:  []string{"rutracker.org"},
			DirectDomains: []string{"example.ru"},
			UDPSupported:  true,
		})
		decision := policy.Decide(Flow{Protocol: ProtocolUDP, Destination: shared, Domains: []string{"shop.example.ru", "rutracker.org"}})
		if decision.Verdict != VerdictProxy {
			t.Fatalf("%s: expected a shared address to stay in the tunnel, got %+v", mode, decision)
		}
		// Its own name settles it.
		own := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: shared, Domains: []string{"shop.example.ru"}, NameSniffed: true})
		if own.Verdict != VerdictDirect || own.Reason != "direct-list" {
			t.Fatalf("%s: expected the flow's own direct-list name to release it, got %+v", mode, own)
		}
	}
}

func TestDirectListAppliesInFullTunnel(t *testing.T) {
	// The "Russian services" list used to be checked after proxy-all had
	// already answered, so full tunnel sent those sites abroad while the PAC
	// sent them direct.
	policy := NewPolicy(Config{
		Mode:          routing.ModeProxyAll,
		DirectDomains: []string{".ru", "yandex.example"},
		UDPSupported:  false,
	})
	for _, domains := range [][]string{{"gosuslugi.ru"}, {"music.yandex.example"}, {"www.example.ru", "cdn.example.ru"}} {
		decision := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: domains})
		if decision.Verdict != VerdictDirect || decision.Reason != "direct-list" {
			t.Fatalf("%v: expected direct-list, got %+v", domains, decision)
		}
	}
	// A learned name the list does not cover keeps the flow in the tunnel.
	if decision := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"www.example.ru", "cdn.example.net"}}); decision.Verdict != VerdictProxy {
		t.Fatalf("expected a partly covered address to stay in the tunnel, got %+v", decision)
	}
	// UDP on a transport without it: a direct-list site's QUIC goes direct
	// instead of being dropped.
	quic := policy.Decide(Flow{Protocol: ProtocolUDP, Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"gosuslugi.ru"}})
	if quic.Verdict != VerdictDirect {
		t.Fatalf("expected a direct-list site's UDP to go direct, got %+v", quic)
	}
	other := policy.Decide(Flow{Protocol: ProtocolUDP, Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"example.com"}})
	if other.Verdict != VerdictDrop {
		t.Fatalf("expected other UDP to be dropped on a transport without it, got %+v", other)
	}
}

func TestNamesAreReadInFullTunnelOnlyWhenTheDirectListCanUseThem(t *testing.T) {
	flow := Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:443"), Domains: []string{"learned.example"}}
	plain := NewPolicy(Config{Mode: routing.ModeProxyAll, Rules: []routing.Rule{domainRule("d", "example.org")}})
	if plain.NameCouldDecide(flow) {
		t.Fatal("full tunnel without a direct list held a flow for its name")
	}
	if NewPolicy(Config{Mode: routing.ModeProxyAll}).NamesMatter() {
		t.Fatal("full tunnel without rules or a direct list made names matter")
	}
	// A domain rule can still claim a flow to the local network, on any port
	// its client names the host on; on a server-speaks-first port the flow is
	// not held, and without a domain rule nothing could claim it.
	if !plain.NameCouldDecide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.168.1.20:443")}) {
		t.Fatal("a web flow to the local network was not read although a domain rule could claim it")
	}
	if plain.NameCouldDecide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.168.1.20:3306")}) {
		t.Fatal("a LAN flow on a server-speaks-first port was held for its name")
	}
	withList := NewPolicy(Config{
		Mode:               routing.ModeProxyAll,
		Rules:              []routing.Rule{{ID: "net", Type: routing.RuleIP, Value: "203.0.113.0/24", Enabled: true}},
		DirectDomains:      []string{".ru"},
		ProtectedEndpoints: []netip.AddrPort{mustAddrPort(t, "198.51.100.4:443")},
		DirectProcesses:    []ProcessIdentity{{PID: 4242, Name: "xray.exe"}},
	})
	if !withList.NamesMatter() || !withList.NameCouldDecide(flow) {
		t.Fatal("full tunnel with a direct list did not ask for the flow's name")
	}
	// Flows settled before any name is read are not held.
	for _, settled := range []Flow{
		{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "198.51.100.4:443")},
		{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "10.0.0.5:443")},
		{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "203.0.113.9:443")},
		{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:443"), ProcessName: "xray.exe", ProcessID: 4242},
	} {
		if withList.NameCouldDecide(settled) {
			t.Fatalf("a settled flow was held for its name: %+v", settled)
		}
	}
	// In selected-rules, names matter for domain rules and the proxy list,
	// not for the direct list alone.
	directOnly := NewPolicy(Config{
		Mode:          routing.ModeSelectedRules,
		Rules:         []routing.Rule{processRule("p", "app.exe")},
		DirectDomains: []string{".ru"},
	})
	if directOnly.NamesMatter() {
		t.Fatal("the direct list alone made names matter in selected-rules")
	}
	proxyList := NewPolicy(Config{Mode: routing.ModeSelectedRules, ProxyDomains: []string{"example.org"}})
	if !proxyList.NameCouldDecide(flow) {
		t.Fatal("the proxy list did not make an unmatched flow's name matter")
	}
}

func TestADomainRuleReachesAHostBehindTheServerOnAnyClientFirstPort(t *testing.T) {
	// pve.home.example resolves to a private address that is not on-link, so
	// the capture routes hand it to the adapter, but its DNS answer came from
	// the cache, the hosts file or DoH and was never seen. Only the flow's own
	// hello names it, and the domain rule beats the local network only if
	// that hello is read - on Proxmox's 8006 or a NAS's 5001 as on 443.
	for _, mode := range []routing.Mode{routing.ModeSelectedRules, routing.ModeProxyAll} {
		policy := NewPolicy(Config{Mode: mode, Rules: []routing.Rule{domainRule("d1", "home.example")}})
		for _, port := range []string{"443", "80", "8006", "5001", "3000", "8080", "8443"} {
			nameless := Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "10.8.0.5:"+port)}
			if decision := policy.Decide(nameless); decision.Verdict != VerdictDirect || decision.Reason != "local-destination" {
				t.Fatalf("%s :%s: expected a nameless flow to stay local, got %+v", mode, port, decision)
			}
			if !policy.NameWorthReading(nameless) {
				t.Fatalf("%s :%s: a LAN flow a domain rule could claim was not read for its name", mode, port)
			}
			named := nameless
			named.Domains = []string{"pve.home.example"}
			named.NameSniffed = true
			if decision := policy.Decide(named); decision.Verdict != VerdictProxy || decision.Reason != "domain" || decision.RuleID != "d1" {
				t.Fatalf("%s :%s: expected the domain rule to claim the named flow, got %+v", mode, port, decision)
			}
		}
		// A server that speaks first gets no name from its client: those
		// flows are not held, and a QUIC flow on any port still is.
		for _, port := range []string{"22", "3306", "25"} {
			if policy.NameWorthReading(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "10.8.0.5:"+port)}) {
				t.Fatalf("%s :%s: a LAN flow on a server-speaks-first port was held for its name", mode, port)
			}
		}
		if !policy.NameWorthReading(Flow{Protocol: ProtocolUDP, Destination: mustAddrPort(t, "10.8.0.5:8443")}) {
			t.Fatalf("%s: a LAN datagram flow a domain rule could claim was not read for its name", mode)
		}
	}
	// Without a domain rule nothing could claim the LAN flow.
	none := NewPolicy(Config{Mode: routing.ModeSelectedRules, ProxyDomains: []string{"blocked.example"}})
	if none.NameWorthReading(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "10.8.0.5:8006")}) {
		t.Fatal("a LAN flow was held although no domain rule could claim it")
	}
}

func TestTunnelledWebFlowsAreReadForTheirNameWhateverSelectedThem(t *testing.T) {
	// Full tunnel with no direct list, and a process rule's own flows: no
	// name can move them to another rule or list, but a single-label name
	// keeps them on the local network and a blocked site's name is what
	// they are dialled by.
	web := Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:443")}
	full := NewPolicy(Config{Mode: routing.ModeProxyAll, ProxyDomains: []string{"blocked.example"}})
	if full.NameCouldDecide(web) || !full.NameWorthReading(web) {
		t.Fatal("full tunnel did not read a web flow's name")
	}
	plain := Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:80")}
	if !NewPolicy(Config{Mode: routing.ModeProxyAll}).NameWorthReading(plain) {
		t.Fatal("full tunnel without lists did not read a plain HTTP flow's name")
	}
	selected := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{processRule("p", "chrome.exe")}, ProxyDomains: []string{"blocked.example"}})
	chrome := web
	chrome.ProcessName = "chrome.exe"
	if selected.NameCouldDecide(chrome) || !selected.NameWorthReading(chrome) {
		t.Fatal("a process rule's web flow was not read for its name")
	}
	// Flows that would go direct anyway, other ports, datagrams and the
	// transport's own traffic are not held for it.
	for _, settled := range []Flow{
		{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "192.0.2.10:22")},
		{Protocol: ProtocolUDP, Destination: mustAddrPort(t, "192.0.2.10:443")},
		{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "10.0.0.5:443")},
	} {
		if full.NameWorthReading(settled) {
			t.Fatalf("held for its name: %+v", settled)
		}
	}
	firefox := web
	firefox.ProcessName = "firefox.exe"
	unselected := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{processRule("p", "chrome.exe")}})
	if unselected.NameWorthReading(firefox) {
		t.Fatal("an unselected flow was held although no name could select it")
	}
	transport := NewPolicy(Config{Mode: routing.ModeProxyAll, DirectProcesses: []ProcessIdentity{{PID: 4242, Name: "xray.exe"}}})
	xray := web
	xray.ProcessName = "xray.exe"
	xray.ProcessID = 4242
	if transport.NameWorthReading(xray) {
		t.Fatal("the transport's own dial was held for its name")
	}
}

func TestOwnerIsOnlyNeededWhenItCanChangeTheVerdict(t *testing.T) {
	flow := func(destination string, domains ...string) Flow {
		return Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, destination), Domains: domains}
	}
	none := NewPolicy(Config{Mode: routing.ModeProxyAll, DirectDomains: []string{".ru"}})
	if none.OwnerMatters(flow("192.0.2.10:443")) {
		t.Fatal("a revision without process rules or transport processes asked for the owner")
	}

	transport := NewPolicy(Config{
		Mode:            routing.ModeSelectedRules,
		ProxyDomains:    []string{"blocked.example"},
		DirectProcesses: []ProcessIdentity{{PID: 4242, Name: "xray.exe"}},
	})
	if transport.OwnerMatters(flow("192.0.2.10:443", "unlisted.example")) {
		t.Fatal("a flow going direct anyway was attributed for the transport's process")
	}
	if !transport.OwnerMatters(flow("192.0.2.10:443", "www.blocked.example")) {
		t.Fatal("a proxied flow was not checked against the transport's process")
	}
	if transport.OwnerMatters(flow("10.0.0.5:443", "www.blocked.example")) {
		t.Fatal("a private destination was attributed")
	}
	// A rule for the local network tunnels it, and the transport's own
	// process still has to be told apart.
	lanRule := NewPolicy(Config{
		Mode:            routing.ModeSelectedRules,
		Rules:           []routing.Rule{{ID: "lan", Type: routing.RuleIP, Value: "10.0.0.0/8", Enabled: true}},
		DirectProcesses: []ProcessIdentity{{PID: 4242, Name: "xray.exe"}},
	})
	if !lanRule.OwnerMatters(flow("10.0.0.5:443")) {
		t.Fatal("a private destination a rule tunnels was not checked against the transport's process")
	}

	rules := NewPolicy(Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{processRule("p", "app.exe")}})
	if !rules.OwnerMatters(flow("192.0.2.10:443")) {
		t.Fatal("an unselected flow was not checked against the process rules")
	}
	if rules.OwnerMatters(flow("[::1]:8080")) {
		t.Fatal("a loopback flow was attributed")
	}
}

func TestOnlyNamesTheRulesSelectByNameAreDialledByName(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:         routing.ModeProxyAll,
		Rules:        []routing.Rule{domainRule("d", "example.org"), {ID: "ip", Type: routing.RuleIP, Value: "203.0.113.0/24", Enabled: true}},
		ProxyDomains: []string{".ua", "blocked.example"},
	})
	for name, want := range map[string]bool{
		"www.example.org":     true,  // a user domain rule
		"news.example.ua":     true,  // the proxy list, by suffix
		"cdn.blocked.example": true,  // the proxy list
		"www.microsoft.com":   false, // a name a REALITY client might borrow
		"example.net":         false,
		"":                    false,
	} {
		if got := policy.DialsByName(name); got != want {
			t.Fatalf("DialsByName(%q) = %v, want %v", name, got, want)
		}
	}
	if NewPolicy(Config{Mode: routing.ModeProxyAll}).DialsByName("www.example.org") {
		t.Fatal("a revision without names dialled by name")
	}
}

func TestPolicySkipsAnInvalidRuleAndKeepsTheRest(t *testing.T) {
	policy := NewPolicy(Config{
		Mode: routing.ModeSelectedRules,
		Rules: []routing.Rule{
			{ID: "zero", Type: routing.RuleIP, Value: "10.0.0.0/08", Enabled: true},
			{ID: "net", Type: routing.RuleIP, Value: "203.0.113.0/24", Enabled: true},
		},
	})
	decision := policy.Decide(Flow{Protocol: ProtocolTCP, Destination: mustAddrPort(t, "203.0.113.9:443")})
	if decision.Verdict != VerdictProxy || decision.RuleID != "net" {
		t.Fatalf("expected the valid rule to keep selecting, got %+v", decision)
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

func TestHysteria2HopPortsAreNeverTunnelled(t *testing.T) {
	// Port hopping sends QUIC to every port in the range. Where the server has
	// no host route, a captured hop would be proxied back into Xray itself.
	policy := NewPolicy(Config{
		Mode: routing.ModeProxyAll,
		ProtectedEndpoints: []netip.AddrPort{
			mustAddrPort(t, "198.51.100.4:443"),
			mustAddrPort(t, "[2001:db8::4]:443"),
		},
		ProtectedPorts: []PortRange{{First: 443, Last: 443}, {First: 20000, Last: 30000}},
		UDPSupported:   true,
	})

	for _, destination := range []string{
		"198.51.100.4:443",
		"198.51.100.4:20000",
		"198.51.100.4:25000",
		"198.51.100.4:30000",
		"[::ffff:198.51.100.4]:25000",
		"[2001:db8::4]:20001",
	} {
		decision := policy.Decide(Flow{
			Protocol:    ProtocolUDP,
			Destination: mustAddrPort(t, destination),
			ProcessName: "xray.exe",
		})
		if decision.Verdict != VerdictDirect || decision.Reason != "protected-ssh-connection" {
			t.Fatalf("expected hop port %s to stay direct, got %+v", destination, decision)
		}
	}

	// A port outside the list on the same host, and a listed port on any other
	// host, are ordinary traffic.
	for _, destination := range []string{"198.51.100.4:19999", "198.51.100.4:30001", "198.51.100.4:8443", "198.51.100.5:25000"} {
		decision := policy.Decide(Flow{Protocol: ProtocolUDP, Destination: mustAddrPort(t, destination)})
		if decision.Verdict != VerdictProxy || decision.Reason != "proxy-all" {
			t.Fatalf("expected %s to be routed normally, got %+v", destination, decision)
		}
	}
}

func TestHopPortsDoNotProtectAHostThatIsNotTheTransport(t *testing.T) {
	// Without a protected endpoint there is no address for the ports to belong
	// to: a port number alone must never exempt a flow.
	policy := NewPolicy(Config{
		Mode:           routing.ModeProxyAll,
		ProtectedPorts: []PortRange{{First: 20000, Last: 30000}},
		UDPSupported:   true,
	})
	decision := policy.Decide(Flow{Protocol: ProtocolUDP, Destination: mustAddrPort(t, "198.51.100.4:25000")})
	if decision.Verdict != VerdictProxy {
		t.Fatalf("expected a hop port on an unprotected host to be routed normally, got %+v", decision)
	}
}

func TestPortRangeContainsItsEnds(t *testing.T) {
	span := PortRange{First: 20000, Last: 30000}
	for port, want := range map[uint16]bool{19999: false, 20000: true, 25000: true, 30000: true, 30001: false} {
		if got := span.Contains(port); got != want {
			t.Fatalf("Contains(%d) = %v, want %v", port, got, want)
		}
	}
	if single := (PortRange{First: 443, Last: 443}); !single.Contains(443) || single.Contains(444) {
		t.Fatalf("a single-port range must contain exactly its port: %+v", single)
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
