// Package dataplane decides and carries traffic for the TUN interception path.
//
// The policy in this file is a port of `LocalRoutingEnforcer.decide` in
// src/service/local-routing-enforcement.ts. The two must stay identical: the
// system-proxy listener and the TUN dataplane are two front doors onto the same
// rule set, and a user who moves between them must not see routing change.
// Every ordering decision below is annotated with the TypeScript behaviour it
// mirrors; the one deliberate difference is UDP, explained on Verdict.
package dataplane

import (
	"net/netip"
	"strings"

	"shadowssh/service/internal/routing"
)

// Verdict is what the dataplane does with one flow.
//
// The system-proxy path only ever has two answers, because a connection it
// declines is simply given an ordinary socket. TUN owns the default route, so
// "not tunnelled" and "not sent at all" become different outcomes and the
// difference matters: SSH cannot carry datagrams, and letting a selected
// application's UDP out through the physical interface would leak exactly the
// traffic its rule exists to capture. Such a flow is dropped instead, which
// makes QUIC clients fall back to TCP, which is tunnelled.
type Verdict int

const (
	// VerdictDirect sends the flow out the physical interface unchanged.
	VerdictDirect Verdict = iota
	// VerdictProxy sends the flow through the transport.
	VerdictProxy
	// VerdictDrop refuses the flow. Reserved for traffic that was selected for
	// the tunnel but cannot be carried by it.
	VerdictDrop
)

func (v Verdict) String() string {
	switch v {
	case VerdictProxy:
		return "proxy"
	case VerdictDrop:
		return "drop"
	default:
		return "direct"
	}
}

// Protocol is the transport protocol of a flow.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Flow describes one connection attempt seen on the TUN adapter.
type Flow struct {
	Protocol Protocol
	// Destination is always known here: TUN sees packets, not proxy requests.
	Destination netip.AddrPort
	// Domains are the names the destination address was learned from, most
	// specific first: the name the application asked for, then the aliases a
	// CNAME chain resolved through. Empty when the application resolved
	// elsewhere or connected to a literal address.
	//
	// More than one is needed because a rule may name either end of a chain -
	// `discord.com` or the CDN host it points at - and both must match.
	Domains []string
	// ProcessName is the lowercase image name of the owning process, or empty
	// when attribution failed.
	ProcessName string
}

// Decision is a verdict plus the rule that produced it, for diagnostics.
type Decision struct {
	Verdict Verdict
	Reason  string
	RuleID  string
}

// Config is one routing revision.
type Config struct {
	Mode          routing.Mode
	Rules         []routing.Rule
	ProxyDomains  []string
	DirectDomains []string
	// ProtectedEndpoints are the transport's own servers. Routing one into the
	// tunnel it carries would deadlock the transport, so they stay direct
	// whatever the rules say. A host that resolved to several addresses
	// contributes all of them.
	ProtectedEndpoints []netip.AddrPort
	// UDPSupported reports whether the active transport can carry datagrams.
	// Xray can (UDP ASSOCIATE); the SSH connection protocol cannot.
	UDPSupported bool
}

// Policy compiles one routing revision into the lookup structures the hot path
// needs. A curated proxy list holds tens of thousands of domains, so it is
// compiled once per revision rather than per flow.
type Policy struct {
	config         Config
	matcher        routing.Matcher
	processNames   map[string]string
	proxySuffixes  map[string]struct{}
	directSuffixes map[string]struct{}
}

// NewPolicy compiles cfg. The result is immutable and safe for concurrent use.
func NewPolicy(cfg Config) *Policy {
	policy := &Policy{
		config:         cfg,
		matcher:        routing.NewMatcher(cfg.Mode, cfg.Rules),
		processNames:   enabledProcessRuleNames(cfg.Rules),
		proxySuffixes:  domainSuffixSet(cfg.ProxyDomains),
		directSuffixes: domainSuffixSet(cfg.DirectDomains),
	}
	return policy
}

// Config returns the revision this policy was compiled from.
func (p *Policy) Config() Config {
	return p.config
}

// Decide answers one flow.
//
// The order is the order in local-routing-enforcement.ts and the reasons are
// the same strings, so a diagnostics line means the same thing on both paths.
func (p *Policy) Decide(flow Flow) Decision {
	// The transport's own endpoint first, before anything can select it. This
	// mirrors TrafficPolicy.isProtectedSshConnection, which runs ahead of the
	// matcher and cannot be overridden by a process rule.
	if p.isProtectedEndpoint(flow.Destination) {
		return Decision{Verdict: VerdictDirect, Reason: "protected-ssh-connection"}
	}

	selected := p.selects(flow)
	if flow.Protocol == ProtocolUDP && !p.config.UDPSupported {
		// See Verdict: a selected flow the transport cannot carry is refused
		// rather than leaked. An unselected one was never ours to carry.
		if selected.Verdict == VerdictProxy {
			return Decision{Verdict: VerdictDrop, Reason: "udp-not-supported", RuleID: selected.RuleID}
		}
		return Decision{Verdict: VerdictDirect, Reason: "udp-not-supported"}
	}
	return selected
}

// selects applies the rule order without the UDP and protected-endpoint
// questions, which Decide answers around it.
func (p *Policy) selects(flow Flow) Decision {
	// The matcher takes one name at a time, so a chain is walked in order and
	// the first name that matches wins - the same first-match semantics the
	// TypeScript matcher applies to its single name.
	matched := routing.Decision{Reason: "no-match"}
	for _, descriptor := range p.descriptors(flow) {
		matched = p.matcher.Decide(descriptor)
		if matched.ShouldProxy {
			break
		}
	}

	// A `process.name` rule means "route everything this application sends", so
	// it is checked before the direct list and cannot be pre-empted by it. This
	// is the same override the TypeScript enforcer applies after the matcher.
	if flow.ProcessName != "" {
		if ruleID, ok := p.processNames[NormalizeProcessName(flow.ProcessName)]; ok {
			return Decision{Verdict: VerdictProxy, Reason: "process.name", RuleID: ruleID}
		}
	}
	if matched.ShouldProxy {
		return Decision{Verdict: VerdictProxy, Reason: matched.Reason, RuleID: matched.RuleID}
	}
	// The curated lists are not expressible as routing rules - their entries
	// include bare suffixes such as `.ua` - so they are matched separately with
	// the domain-or-parent semantics the PAC applies to them.
	for _, domain := range flow.Domains {
		if domainCoveredBySuffixes(domain, p.proxySuffixes) {
			return Decision{Verdict: VerdictProxy, Reason: "proxy-list"}
		}
	}
	for _, domain := range flow.Domains {
		if domainCoveredBySuffixes(domain, p.directSuffixes) {
			return Decision{Verdict: VerdictDirect, Reason: "direct-list"}
		}
	}
	return Decision{Verdict: VerdictDirect, Reason: matched.Reason}
}

// descriptors renders one matcher input per known name, and one without a name
// at all so an address-only flow is still matched against IP rules.
func (p *Policy) descriptors(flow Flow) []routing.Descriptor {
	base := routing.Descriptor{
		DestinationIP:   flow.Destination.Addr().String(),
		DestinationPort: int(flow.Destination.Port()),
		ProcessName:     flow.ProcessName,
		// Protocol is deliberately not forwarded: routing.Matcher refuses UDP
		// outright, and the transport-aware answer is Decide's job.
	}
	if len(flow.Domains) == 0 {
		return []routing.Descriptor{base}
	}
	descriptors := make([]routing.Descriptor, 0, len(flow.Domains))
	for _, domain := range flow.Domains {
		withDomain := base
		withDomain.DestinationDomain = domain
		descriptors = append(descriptors, withDomain)
	}
	return descriptors
}

// HasProcessRules reports whether this revision selects anything by process,
// which is the only reason the TUN path is worth its cost over the system
// proxy.
func (p *Policy) HasProcessRules() bool {
	return len(p.processNames) > 0
}

func (p *Policy) isProtectedEndpoint(destination netip.AddrPort) bool {
	for _, protected := range p.config.ProtectedEndpoints {
		if !protected.IsValid() || protected.Port() != destination.Port() {
			continue
		}
		if protected.Addr().Unmap() == destination.Addr().Unmap() {
			return true
		}
	}
	return false
}

func enabledProcessRuleNames(rules []routing.Rule) map[string]string {
	names := make(map[string]string)
	for _, rule := range rules {
		if !rule.Enabled || rule.Type != routing.RuleProcessName || !validProcessRuleValue(rule.Value) {
			continue
		}
		name := NormalizeProcessName(rule.Value)
		if name == "" {
			continue
		}
		// First enabled rule wins, matching the Map-insertion semantics the
		// TypeScript matcher documents for duplicate values.
		if _, exists := names[name]; !exists {
			names[name] = rule.ID
		}
	}
	return names
}

// validProcessRuleValue mirrors validateProcessName in
// src/shared/validation.ts. A rule the UI would have rejected must not match
// here either: the two paths would otherwise disagree about which
// applications are selected, which is the one thing a user cannot debug.
func validProcessRuleValue(value string) bool {
	name := strings.TrimSpace(value)
	if name == "" || len(name) > 260 || strings.ContainsAny(name, `/\`) {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := lowerASCII(name[index])
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && !strings.ContainsRune("._+- ", rune(character)) {
			return false
		}
	}
	return true
}

// NormalizeProcessName mirrors normalizeWindowsProcessName in
// src/core/network/windows-process-connections.ts, including the part that is
// easy to miss: a name without an extension gets `.exe` appended, so a rule
// typed as `discord` still matches the `discord.exe` the socket table reports.
// Omitting that made such a rule silently inert - and an inert process rule is
// a leak, not a no-op.
//
// The leading directory is also dropped, which the TypeScript does not need to
// do because its inputs are already bare names. Doing it here only ever makes a
// path-shaped input match the rule it obviously means; a path-shaped *rule* is
// rejected by validProcessRuleValue, exactly as the UI rejects it.
func NormalizeProcessName(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if index := strings.LastIndexAny(trimmed, `/\`); index >= 0 {
		trimmed = trimmed[index+1:]
	}
	if trimmed == "" || strings.HasSuffix(trimmed, ".exe") {
		return trimmed
	}
	return trimmed + ".exe"
}

func domainSuffixSet(domains []string) map[string]struct{} {
	suffixes := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		normalized := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."), ".")
		normalized = strings.TrimSuffix(normalized, ".")
		if normalized != "" {
			suffixes[normalized] = struct{}{}
		}
	}
	return suffixes
}

// domainCoveredBySuffixes walks label boundaries so lookup is proportional to
// domain depth rather than list size, which matters for lists with tens of
// thousands of entries.
func domainCoveredBySuffixes(domain string, suffixes map[string]struct{}) bool {
	if len(suffixes) == 0 {
		return false
	}
	candidate := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for candidate != "" {
		if _, ok := suffixes[candidate]; ok {
			return true
		}
		dot := strings.Index(candidate, ".")
		if dot < 0 {
			return false
		}
		candidate = candidate[dot+1:]
	}
	return false
}
