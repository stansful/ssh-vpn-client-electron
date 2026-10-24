// Package dataplane decides and carries traffic for the TUN interception path.
//
// The policy in this file applies the routing order every path shares: this
// dataplane, `LocalRoutingEnforcer.decide` in
// src/service/local-routing-enforcement.ts, and the PAC built by buildProxyPac.
// They must stay identical: the paths are front doors onto the same rule set,
// and a user who moves between them must not see routing change. The order is
//
//  1. the transport's own endpoint                       -> direct
//     1.5. a flow owned by one of DirectProcesses        -> direct
//  2. an enabled domain or IP rule matches               -> proxy
//  3. a local or private destination                     -> direct
//  4. an enabled process.name rule matches the owner     -> proxy
//  5. the destination is on the direct list              -> direct
//  6. routing mode proxy-all                             -> proxy
//  7. the destination is on the proxy list               -> proxy
//  8. otherwise                                          -> direct
//
// An explicit rule wins (step 2 before step 3): a rule for a private range or
// a `.local` name is how a user reaches the network behind the server. A
// process rule does not (step 4 after step 3): it selects what an application
// sends to the internet, not its LAN traffic.
//
// The reasons are the same strings on every path, so a diagnostics line
// means the same thing wherever it was written. The deliberate differences are
// UDP, explained on Verdict, and the transport's extra ports and processes,
// explained on Config.ProtectedPorts and Config.DirectProcesses. The PAC is the
// one path that cannot hold step 4 where it is - it cannot tell which
// application asks - so it checks what discovery learned for a process rule
// after the direct list, and only in selected-rules (see TrafficPolicy in
// src/core/routing/traffic-policy.ts). Here a process rule pulls its
// application's direct-list sites into the tunnel in either mode.
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
	//
	// Learned names are only labels for the address: one address serves many
	// sites, and whoever answered the lookup - the local resolver, which may
	// be hostile - chose them. So any of them may select a flow (steps 2 and
	// 7), but releasing one takes more: the direct list must cover every name
	// (step 5), and a local-only name (step 3) counts only when it is the
	// flow's own, below.
	Domains []string
	// NameSniffed reports that Domains is the one name the flow itself
	// carried - its TLS server name, HTTP Host or QUIC server name - rather
	// than names its address was learned under.
	NameSniffed bool
	// ProcessName is the lowercase image name of the owning process, or empty
	// when attribution failed or was not needed (see Policy.OwnerMatters).
	ProcessName string
	// ProcessID is the owning process's ID, or 0 when it is not known.
	ProcessID uint32
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
	// ProtectedPorts are further ports of the same servers that the transport
	// uses: a Hysteria 2 client hops its QUIC across a whole range of them, and
	// any one captured would be proxied back into Xray. They apply to the
	// addresses of ProtectedEndpoints only, whatever the protocol.
	//
	// The host route installed for each server is what normally keeps these
	// flows out of the adapter; this guard covers the cases where there is no
	// such route. The TypeScript policy has no equivalent because Xray's own
	// sockets never pass through the system-proxy listener.
	ProtectedPorts []PortRange
	// DirectProcesses are the transport's own processes, whose flows always
	// go direct, right after the transport's endpoint. Xray dials its server
	// by name, and a CDN-fronted server can answer with an address the host
	// routes for ProtectedEndpoints do not cover; captured and proxied, that
	// dial would be sent back into Xray's own inbound.
	//
	// A process is picked out by its ID, not by its file name: every other
	// program called xray.exe - another client's own core, or anything renamed
	// to it - must be routed like any application, a process rule naming it
	// included. The name, when given, must match as well, so an ID Windows
	// hands to another program once the transport's process is gone does not
	// carry the exemption with it.
	DirectProcesses []ProcessIdentity
	// UDPSupported reports whether the active transport can carry datagrams.
	// Xray can (UDP ASSOCIATE); the SSH connection protocol cannot.
	UDPSupported bool
}

// ProcessIdentity is one running process: its ID, and the image name it must
// have, compared like a process rule (case-insensitively, on the bare file
// name, with `.exe` implied). An empty name matches any.
type ProcessIdentity struct {
	PID  uint32
	Name string
}

// PortRange is an inclusive span of ports, First <= Last. A single port is a
// range whose ends are equal.
type PortRange struct {
	First uint16
	Last  uint16
}

// Contains reports whether port falls inside the range.
func (r PortRange) Contains(port uint16) bool {
	return r.First <= port && port <= r.Last
}

// The reasons a decision can carry besides the matcher's own ("domain", "ip",
// "no-match", "no-enabled-rules"). They are shared with the TypeScript paths.
const (
	reasonProtectedEndpoint = "protected-ssh-connection"
	reasonDirectProcess     = "direct-process"
	reasonLocalDestination  = "local-destination"
	reasonProcessRule       = "process.name"
	reasonDirectList        = "direct-list"
	reasonProxyAll          = "proxy-all"
	reasonProxyList         = "proxy-list"
	reasonUDPNotSupported   = "udp-not-supported"
)

// Policy compiles one routing revision into the lookup structures the hot path
// needs. A curated proxy list holds tens of thousands of domains, so it is
// compiled once per revision rather than per flow.
type Policy struct {
	config Config
	// rules matches the user's domain and IP rules. It is compiled for
	// selected-rules whatever the mode: in proxy-all a user rule still has to
	// win over the local network and the direct list (step 2 before steps 3
	// and 5), so the matcher must not answer "proxy-all" first.
	rules        routing.Matcher
	domainRules  int
	processNames map[string]string
	// directProcesses maps each transport process's ID to its normalised
	// image name, "" for any.
	directProcesses map[uint32]string
	proxySuffixes   map[string]struct{}
	directSuffixes  map[string]struct{}
}

// NewPolicy compiles cfg. The result is immutable and safe for concurrent use.
func NewPolicy(cfg Config) *Policy {
	rules := routing.NewMatcher(routing.ModeSelectedRules, cfg.Rules)
	return &Policy{
		config:          cfg,
		rules:           rules,
		domainRules:     rules.Summary().DomainRules,
		processNames:    enabledProcessRuleNames(cfg.Rules),
		directProcesses: processIdentitySet(cfg.DirectProcesses),
		proxySuffixes:   domainSuffixSet(cfg.ProxyDomains),
		directSuffixes:  domainSuffixSet(cfg.DirectDomains),
	}
}

// Config returns the revision this policy was compiled from.
func (p *Policy) Config() Config {
	return p.config
}

// Decide answers one flow: the shared order, then what the transport can
// carry.
func (p *Policy) Decide(flow Flow) Decision {
	decision := p.route(flow)
	if flow.Protocol != ProtocolUDP || p.config.UDPSupported {
		return decision
	}
	switch decision.Reason {
	case reasonProtectedEndpoint, reasonDirectProcess, reasonLocalDestination:
		// The transport, its process, or the local network no rule named:
		// these were never the tunnel's to carry.
		return decision
	}
	// See Verdict: a selected flow the transport cannot carry is refused
	// rather than leaked. An unselected one was never ours to carry.
	if decision.Verdict == VerdictProxy {
		return Decision{Verdict: VerdictDrop, Reason: reasonUDPNotSupported, RuleID: decision.RuleID}
	}
	return Decision{Verdict: VerdictDirect, Reason: reasonUDPNotSupported}
}

// route applies the shared order (see the package comment) without the UDP
// question, which Decide answers around it.
func (p *Policy) route(flow Flow) Decision {
	// 1. The transport's own endpoint, before anything can select it. This
	// mirrors TrafficPolicy.isProtectedSshConnection and cannot be overridden by
	// any rule. It also covers the server's hop ports, which the TypeScript
	// never sees.
	if p.isProtectedEndpoint(flow.Destination) {
		return Decision{Verdict: VerdictDirect, Reason: reasonProtectedEndpoint}
	}
	// 1.5. The transport's own process: whatever it dials is the transport.
	if p.isDirectProcess(flow) {
		return Decision{Verdict: VerdictDirect, Reason: reasonDirectProcess}
	}
	// 2. The user's own domain and IP rules, ahead of the local network: an
	// explicit rule for a private range or a `.local` name means "reach it
	// through the tunnel". The matcher takes one name at a time, so a chain is
	// walked in order and the first name that matches wins - the same
	// first-match semantics the TypeScript matcher applies to its single name.
	// Any learned name may select, as on step 7.
	matched := routing.Decision{Reason: "no-match"}
	for _, descriptor := range p.descriptors(flow) {
		matched = p.rules.Decide(descriptor)
		if matched.ShouldProxy {
			return Decision{Verdict: VerdictProxy, Reason: matched.Reason, RuleID: matched.RuleID}
		}
	}
	// 3. The machine itself and the networks around it, judged on the real
	// address. A name that can only mean the local network counts when the
	// flow named it itself, as the system-proxy paths judge the name they are
	// asked for: a learned one - a CNAME a resolver planted beside a public
	// address, another flow's SNI - must not pull every flow to that address
	// out of the tunnel, ahead of process rules and full tunnel.
	if isLocalAddress(flow.Destination.Addr()) || (flow.NameSniffed && anyLocalName(flow.Domains)) {
		return Decision{Verdict: VerdictDirect, Reason: reasonLocalDestination}
	}
	// 4. A `process.name` rule means "route everything this application
	// sends" past the local network, so no list can carve a hole in it.
	if ruleID, ok := p.processRule(flow.ProcessName); ok {
		return Decision{Verdict: VerdictProxy, Reason: reasonProcessRule, RuleID: ruleID}
	}
	// 5-7. The curated lists are not expressible as routing rules - their
	// entries include bare suffixes such as `.ua` - so they are matched
	// separately with the domain-or-parent semantics the PAC applies to them.
	// The direct list comes before proxy-all, so "Russian services" stay
	// direct in full tunnel too, and before the proxy list, so a narrower
	// direct entry wins over a broader proxy one. It releases a flow only
	// when it covers every name the flow is known by: an address shared by a
	// direct-list site and a blocked one says nothing about which this flow
	// is for, and the tunnel is the side to err on.
	if allDomainsCovered(flow.Domains, p.directSuffixes) {
		return Decision{Verdict: VerdictDirect, Reason: reasonDirectList}
	}
	if p.config.Mode == routing.ModeProxyAll {
		return Decision{Verdict: VerdictProxy, Reason: reasonProxyAll}
	}
	if anyDomainCovered(flow.Domains, p.proxySuffixes) {
		return Decision{Verdict: VerdictProxy, Reason: reasonProxyList}
	}
	// 8. Nothing selected it.
	return Decision{Verdict: VerdictDirect, Reason: matched.Reason}
}

// descriptors renders one matcher input per known name, and one without a name
// at all so an address-only flow is still matched against IP rules. The
// process is left out: step 4 answers for it, with the `.exe` normalisation
// the matcher does not apply. An IPv4-mapped address is matched as the IPv4
// address it carries, as isLocalAddress and the TypeScript matcher read it.
func (p *Policy) descriptors(flow Flow) []routing.Descriptor {
	base := routing.Descriptor{
		DestinationIP:   flow.Destination.Addr().WithZone("").Unmap().String(),
		DestinationPort: int(flow.Destination.Port()),
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

// NamesMatter reports whether a name can ever change the answer an address
// gave: a domain rule can select a flow - in selected-rules any flow, in
// proxy-all one to the local network, which it wins over (step 2 before step
// 3) - the proxy list can select one in selected-rules, and the direct list
// can release one in proxy-all. Only then is it worth holding a flow back to
// read its name from its first bytes. The direct list does not count in
// selected-rules, because it can only release what the proxy list selected,
// and the proxy list needs a name to begin with.
func (p *Policy) NamesMatter() bool {
	if p.domainRules > 0 {
		return true
	}
	if p.config.Mode == routing.ModeProxyAll {
		return len(p.directSuffixes) > 0
	}
	return len(p.proxySuffixes) > 0
}

// NameCouldDecide reports whether learning the flow's own name could still
// change how it is routed. The names the flow already carries are set aside:
// one CDN address serves many sites, and only the flow's own name says which
// one this is. A flow settled before any name is consulted - the transport,
// its process, an address rule, a process rule - is not; nor is one to the
// local network unless a domain rule could claim it. Such a flow is read on
// any port a client can name its host on - the hosts behind the server that
// a domain rule reaches serve HTTPS on 8006, 5001 or 8443 as often as on 443,
// and their names are seldom seen in DNS - except the well-known ports whose
// server speaks first (isServerFirstPort): their client sends no name, so
// every LAN connection there would wait out the sniff window for nothing.
func (p *Policy) NameCouldDecide(flow Flow) bool {
	if !p.NamesMatter() {
		return false
	}
	nameless := flow
	nameless.Domains = nil
	nameless.NameSniffed = false
	switch p.route(nameless).Reason {
	case reasonProxyAll:
		// Step 6: only the direct list (step 5) changes the verdict; a domain
		// rule would tunnel it all the same.
		return len(p.directSuffixes) > 0
	case "no-match", "no-enabled-rules":
		// Step 8: a domain rule (step 2) or the proxy list (step 7) can select it.
		return p.domainRules > 0 || len(p.proxySuffixes) > 0
	case reasonLocalDestination:
		// Step 3: a domain rule naming it (step 2) wins over the local network.
		if flow.Protocol == ProtocolTCP && isServerFirstPort(flow.Destination.Port()) {
			return false
		}
		return p.domainRules > 0
	default:
		return false
	}
}

// NameWorthReading reports whether a flow is worth holding back to read its
// own name from its first bytes: when the name could still change where it
// goes (NameCouldDecide), and also for a TCP flow to a web port that would be
// tunnelled whatever it is named - in full tunnel, or selected by a process or
// address rule. For such a flow the name still matters twice: a single-label
// name (`wiki`, resolved by a suffix search to an address outside the private
// ranges) keeps it on the local network (step 3) unless an address rule
// selected it, and a name the rules select is what it is dialled through the
// tunnel by (DialsByName) - as is that of a flow NameCouldDecide held, on any
// port - so a poisoned local answer for a blocked site is not followed. Only
// the web ports are held for this second reason: browsers name their host
// there and speak first, while a protocol whose server speaks first would wait
// out the sniff window for nothing.
func (p *Policy) NameWorthReading(flow Flow) bool {
	if p.NameCouldDecide(flow) {
		return true
	}
	if flow.Protocol != ProtocolTCP || !isWebPort(flow.Destination.Port()) {
		return false
	}
	nameless := flow
	nameless.Domains = nil
	nameless.NameSniffed = false
	return p.route(nameless).Verdict == VerdictProxy
}

// OwnerMatters reports whether the process that owns the flow can change how
// it is routed, so the owner tables are only read for flows whose answer
// turns on them. The transport's endpoint is settled before any process, and
// the local network before process rules (step 3 before step 4) - the
// transport's own process could only send such a flow direct, where it goes
// anyway. While process rules exist every other flow is asked: a process rule
// answers ahead of every list, and a name can move a flow it selects nowhere
// but the local network. With only DirectProcesses, the owner can only
// release a flow that would otherwise be tunnelled - a user rule's included.
// The flow's current ProcessName is set aside; the question is about the
// answer without it.
func (p *Policy) OwnerMatters(flow Flow) bool {
	if len(p.processNames) == 0 && len(p.directProcesses) == 0 {
		return false
	}
	anonymous := flow
	anonymous.ProcessName = ""
	anonymous.ProcessID = 0
	settled := p.route(anonymous)
	switch settled.Reason {
	case reasonProtectedEndpoint, reasonLocalDestination:
		return false
	}
	return len(p.processNames) > 0 || settled.Verdict == VerdictProxy
}

// DialsByName reports whether a tunnelled flow that named its host - its TLS
// server name or the Host of an origin-form HTTP request; the target of a
// request to an HTTP proxy is never its host (namesConnectedServer, checked
// by the caller) - is dialled through the tunnel by that name, so
// the far end resolves it, rather than by the address the local resolver
// gave. That is so exactly when the name is what marks the site for the
// tunnel: a user's domain rule or the proxy list names it. Those are the
// sites a poisoned local answer is aimed at, and the system-proxy paths hand
// their names to the server already. Any other name stays out of the CONNECT:
// applications that borrow a name for their SNI (REALITY, fake-TLS proxies,
// domain fronting) must reach the address they chose, and an OpenSSH server
// resolves a direct-tcpip name synchronously, stalling the whole session.
func (p *Policy) DialsByName(name string) bool {
	if name == "" {
		return false
	}
	if domainCoveredBySuffixes(name, p.proxySuffixes) {
		return true
	}
	return p.domainRules > 0 && p.rules.Decide(routing.Descriptor{DestinationDomain: name}).Reason == "domain"
}

func (p *Policy) processRule(processName string) (string, bool) {
	if processName == "" || len(p.processNames) == 0 {
		return "", false
	}
	ruleID, ok := p.processNames[NormalizeProcessName(processName)]
	return ruleID, ok
}

func (p *Policy) isDirectProcess(flow Flow) bool {
	if flow.ProcessID == 0 || len(p.directProcesses) == 0 {
		return false
	}
	name, ok := p.directProcesses[flow.ProcessID]
	return ok && (name == "" || name == NormalizeProcessName(flow.ProcessName))
}

func (p *Policy) isProtectedEndpoint(destination netip.AddrPort) bool {
	address := destination.Addr().Unmap()
	for _, protected := range p.config.ProtectedEndpoints {
		if !protected.IsValid() || protected.Addr().Unmap() != address {
			continue
		}
		if protected.Port() == destination.Port() || p.isProtectedPort(destination.Port()) {
			return true
		}
	}
	return false
}

func (p *Policy) isProtectedPort(port uint16) bool {
	for _, protected := range p.config.ProtectedPorts {
		if protected.Contains(port) {
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

func processIdentitySet(processes []ProcessIdentity) map[uint32]string {
	set := make(map[uint32]string, len(processes))
	for _, process := range processes {
		if process.PID != 0 {
			set[process.PID] = NormalizeProcessName(process.Name)
		}
	}
	return set
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

// localPrefixes are the destinations that stay on the machine's own networks
// unless a user rule names them (step 3): loopback, the private and shared
// (CGNAT) ranges, link-local, IPv6 unique-local, and "this network". The
// TypeScript paths and the PAC use the same list. The TUN routes already keep
// on-link networks off the adapter; this covers the private ranges that are
// not on-link, which the capture routes would otherwise take - and which an
// IP rule such as 10.0.0.0/8 then sends through the tunnel on purpose.
var localPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// isLocalAddress reports whether address is in localPrefixes, its
// IPv4-mapped IPv6 form included.
func isLocalAddress(address netip.Addr) bool {
	address = address.WithZone("").Unmap()
	if !address.IsValid() {
		return false
	}
	for _, prefix := range localPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// anyLocalName reports whether a name the flow is known by can only mean the
// local network (see isLocalName).
func anyLocalName(domains []string) bool {
	for _, domain := range domains {
		if isLocalName(domain) {
			return true
		}
	}
	return false
}

// isLocalName reports whether a name can only mean the local network:
// "localhost", a single label, or an mDNS `.local` name.
func isLocalName(domain string) bool {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if name == "" {
		return false
	}
	return name == "localhost" || !strings.Contains(name, ".") || strings.HasSuffix(name, ".local")
}

// isWebPort reports whether port is one browsers open sites on, where a flow
// names its host in its first bytes and the client speaks first.
func isWebPort(port uint16) bool {
	return port == 443 || port == 80
}

// isServerFirstPort reports whether port is a well-known TCP port whose
// server speaks first: the client sends nothing - and so no name - until it
// has read the server's greeting, so reading its first bytes only delays the
// connection. FTP, SSH (PuTTY waits for the server's version before sending
// its own), Telnet, SMTP and submission, POP3, IMAP, MySQL and VNC.
func isServerFirstPort(port uint16) bool {
	switch port {
	case 21, 22, 23, 25, 110, 143, 587, 3306, 5900:
		return true
	}
	return false
}

func anyDomainCovered(domains []string, suffixes map[string]struct{}) bool {
	for _, domain := range domains {
		if domainCoveredBySuffixes(domain, suffixes) {
			return true
		}
	}
	return false
}

// allDomainsCovered reports whether there is at least one name and suffixes
// cover every one of them.
func allDomainsCovered(domains []string, suffixes map[string]struct{}) bool {
	if len(domains) == 0 || len(suffixes) == 0 {
		return false
	}
	for _, domain := range domains {
		if !domainCoveredBySuffixes(domain, suffixes) {
			return false
		}
	}
	return true
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
