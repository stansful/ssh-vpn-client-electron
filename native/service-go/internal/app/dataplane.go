package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"shadowssh/service/internal/dataplane"
	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/routing"
)

// The tunnel itself lives in the Electron process; this service only owns the
// interception path. Starting the dataplane is therefore a separate command
// rather than part of `connect`: the transport has to be up, and its loopback
// proxy listening, before there is anywhere to send captured traffic.

// DataplaneStartPayload is the `start-dataplane` command body.
type DataplaneStartPayload struct {
	RoutingMode          routing.Mode   `json:"routingMode"`
	RoutingRules         []routing.Rule `json:"routingRules"`
	RoutingProxyDomains  []string       `json:"routingProxyDomains"`
	RoutingDirectDomains []string       `json:"routingDirectDomains"`
	// TunnelProxyEndpoint is the transport's loopback SOCKS5 inbound,
	// "127.0.0.1:<port>".
	TunnelProxyEndpoint string `json:"tunnelProxyEndpoint"`
	// ProtectedAddresses are the resolved addresses of the transport's own
	// server. The Electron side knows which address it actually connected to,
	// so it sends that rather than a hostname this process would have to
	// resolve again - possibly to a different answer.
	ProtectedAddresses []string `json:"protectedAddresses"`
	ProtectedPort      int      `json:"protectedPort"`
	// ProtectedPorts lists the other ports of the same server the transport
	// sends to, as ports and ranges: "443,20000-30000". Only Hysteria 2 port
	// hopping sends it; it is empty for every other transport.
	ProtectedPorts string `json:"protectedPorts"`
	// UDPSupported reports whether the transport can carry datagrams. Xray can;
	// the SSH connection protocol cannot, and a selected process's UDP is then
	// dropped rather than leaked.
	UDPSupported bool   `json:"udpSupported"`
	EnforceIPv6  bool   `json:"enforceIpv6"`
	AdapterName  string `json:"adapterName"`
	JournalPath  string `json:"journalPath"`
}

const defaultAdapterName = "Shadow SSH"

func (a *App) handleStartDataplane(ctx context.Context, command protocol.Command) protocol.CommandResult {
	var payload DataplaneStartPayload
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	policy, endpoint, protectedAddresses, err := payload.compile()
	if err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	// Everything the adapter and the routing table were built from. A change
	// to any of it cannot be applied by swapping the policy, because the
	// policy does not own the routes.
	signature := payload.infrastructureSignature()

	a.dataplaneMu.Lock()
	defer a.dataplaneMu.Unlock()
	if a.dataplane != nil {
		if a.dataplaneSignature == signature {
			// A routing change while the dataplane is up is a policy swap, not
			// a restart: tearing the adapter down would drop every live
			// connection for a change that only affects the next one.
			a.dataplane.UpdatePolicy(policy)
			a.dataplanePolicy = policy
			return a.ok(command.ID, protocol.Accepted(), diagnostic("info", "TUN dataplane routing policy updated."))
		}
		// A different signature means the transport reconnected, moved its
		// loopback proxy, or changed which servers or ports must stay excluded.
		// Keeping the running dataplane would forward selected flows to a port
		// nothing is listening on, or leave a stale host route behind.
		runner := a.dataplane
		a.dataplane = nil
		a.dataplanePolicy = nil
		a.dataplaneSignature = ""
		teardownCtx, cancel := dataplaneTeardownContext(ctx)
		defer cancel()
		if err := runner.Close(teardownCtx); err != nil {
			return protocol.CommandResult{
				Response: protocol.Error(command.ID, fmt.Errorf("restart dataplane for a new transport endpoint: %w", err)),
				Events:   []any{diagnostic("error", "TUN dataplane teardown before restart failed: "+err.Error())},
			}
		}
	}

	adapterName := strings.TrimSpace(payload.AdapterName)
	if adapterName == "" {
		adapterName = defaultAdapterName
	}
	runner, err := dataplane.StartWindows(ctx, dataplane.WindowsOptions{
		AdapterName:        adapterName,
		JournalPath:        payload.JournalPath,
		Policy:             policy,
		TunnelEndpoint:     endpoint,
		ProtectedAddresses: protectedAddresses,
		EnforceIPv6:        payload.EnforceIPv6,
		Log:                a.logDiagnostic,
	})
	if err != nil {
		return protocol.CommandResult{
			Response: protocol.Error(command.ID, err),
			Events:   []any{diagnostic("warning", "TUN dataplane did not start: "+err.Error())},
		}
	}
	a.dataplane = runner
	a.dataplanePolicy = policy
	a.dataplaneSignature = signature
	return a.ok(command.ID, protocol.Accepted(), diagnostic("info", "TUN dataplane started."))
}

func (a *App) handleStopDataplane(ctx context.Context, command protocol.Command) protocol.CommandResult {
	if err := a.stopDataplane(ctx); err != nil {
		return protocol.CommandResult{
			Response: protocol.Error(command.ID, err),
			Events:   []any{diagnostic("error", "TUN dataplane teardown failed: "+err.Error())},
		}
	}
	return a.ok(command.ID, protocol.Accepted(), diagnostic("info", "TUN dataplane stopped."))
}

// stopDataplane is idempotent so disconnect, shutdown and an explicit stop can
// all call it without coordinating.
//
// The caller's context is deliberately not used for the teardown itself. It is
// routinely already cancelled - the client went away, the service is being
// signalled - and every `netsh` undo would then fail instantly, leaving the
// machine captured with nothing forwarding.
//
// The budget is its own, too. cleanupContext allows five seconds, which is
// right for the no-op ClearRouting it was written for and far too short here: a
// teardown shells out to netsh once per route it installed, and a rollback cut
// off half way is what leaves the next connect unable to bring the adapter back
// up at all.
func (a *App) stopDataplane(ctx context.Context) error {
	a.dataplaneMu.Lock()
	runner := a.dataplane
	a.dataplane = nil
	a.dataplanePolicy = nil
	a.dataplaneSignature = ""
	a.dataplaneMu.Unlock()
	if runner == nil {
		return nil
	}
	teardownCtx, cancel := dataplaneTeardownContext(ctx)
	defer cancel()
	return runner.Close(teardownCtx)
}

// dataplaneTeardownTimeout bounds a whole dataplane teardown: a routing
// rollback plus closing the adapter.
const dataplaneTeardownTimeout = 3 * time.Minute

func dataplaneTeardownContext(parent context.Context) (context.Context, context.CancelFunc) {
	_ = parent
	return context.WithTimeout(context.Background(), dataplaneTeardownTimeout)
}

func (p DataplaneStartPayload) infrastructureSignature() string {
	addresses := append([]string(nil), p.ProtectedAddresses...)
	sort.Strings(addresses)
	return strings.Join([]string{
		strings.TrimSpace(p.TunnelProxyEndpoint),
		strconv.Itoa(p.ProtectedPort),
		// The hop ports install no route of their own, but a new list means a
		// new server profile, the same as a new protectedPort.
		strings.TrimSpace(p.ProtectedPorts),
		strings.Join(addresses, ","),
		strconv.FormatBool(p.EnforceIPv6),
		strconv.FormatBool(p.UDPSupported),
		strings.TrimSpace(p.AdapterName),
		strings.TrimSpace(p.JournalPath),
	}, "|")
}

func (p DataplaneStartPayload) compile() (*dataplane.Policy, netip.AddrPort, []netip.Addr, error) {
	endpoint, err := netip.ParseAddrPort(strings.TrimSpace(p.TunnelProxyEndpoint))
	if err != nil {
		return nil, netip.AddrPort{}, nil, fmt.Errorf("tunnelProxyEndpoint must be host:port: %w", err)
	}
	if !endpoint.Addr().IsLoopback() {
		// The dataplane forwards selected traffic into this endpoint. Anything
		// but loopback would either leave the machine unprotected or be routed
		// straight back into the adapter.
		return nil, netip.AddrPort{}, nil, errors.New("tunnelProxyEndpoint must be on loopback")
	}
	if err := validateRouting(p.RoutingMode, p.RoutingRules, p.RoutingProxyDomains); err != nil {
		return nil, netip.AddrPort{}, nil, err
	}
	// A list that cannot be read is refused rather than skipped: the transport
	// would come up with its hop ports unguarded and only fail where the host
	// route is missing, which is the one place nobody is looking.
	protectedPorts, err := parsePortList(p.ProtectedPorts)
	if err != nil {
		return nil, netip.AddrPort{}, nil, err
	}

	var protectedAddresses []netip.Addr
	var protectedEndpoints []netip.AddrPort
	for _, raw := range p.ProtectedAddresses {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(raw))
		if parseErr != nil {
			return nil, netip.AddrPort{}, nil, fmt.Errorf("protectedAddresses contains %q: %w", raw, parseErr)
		}
		address = address.Unmap()
		protectedAddresses = append(protectedAddresses, address)
		if p.ProtectedPort > 0 && p.ProtectedPort <= 65535 {
			protectedEndpoints = append(protectedEndpoints, netip.AddrPortFrom(address, uint16(p.ProtectedPort)))
		}
	}

	policy := dataplane.NewPolicy(dataplane.Config{
		Mode:               p.RoutingMode,
		Rules:              p.RoutingRules,
		ProxyDomains:       p.RoutingProxyDomains,
		DirectDomains:      p.RoutingDirectDomains,
		ProtectedEndpoints: protectedEndpoints,
		ProtectedPorts:     protectedPorts,
		UDPSupported:       p.UDPSupported,
	})
	return policy, endpoint, protectedAddresses, nil
}

// parsePortList reads a comma-separated list of ports and inclusive ranges,
// "443,20000-30000", in the form hysteria2-link.ts normalises a link's ports
// to. Like that parser it tolerates spaces and puts a reversed range in order.
// An empty list protects no extra ports.
func parsePortList(list string) ([]dataplane.PortRange, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	items := strings.Split(list, ",")
	ranges := make([]dataplane.PortRange, 0, len(items))
	for _, item := range items {
		rawFirst, rawLast, isRange := strings.Cut(item, "-")
		if !isRange {
			rawLast = rawFirst
		}
		first, firstOK := parsePort(rawFirst)
		last, lastOK := parsePort(rawLast)
		if !firstOK || !lastOK {
			return nil, fmt.Errorf("protectedPorts contains %q: expected a port or a range of ports between 1 and 65535", strings.TrimSpace(item))
		}
		if first > last {
			first, last = last, first
		}
		ranges = append(ranges, dataplane.PortRange{First: first, Last: last})
	}
	return ranges, nil
}

func parsePort(raw string) (uint16, bool) {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil || value == 0 {
		return 0, false
	}
	return uint16(value), true
}
