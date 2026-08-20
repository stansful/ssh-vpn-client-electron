package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

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
		// loopback proxy, or changed which servers must stay excluded.
		// Keeping the running dataplane would forward selected flows to a port
		// nothing is listening on, or leave a stale host route behind.
		runner := a.dataplane
		a.dataplane = nil
		a.dataplanePolicy = nil
		a.dataplaneSignature = ""
		teardownCtx, cancel := cleanupContext(ctx)
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
	teardownCtx, cancel := cleanupContext(ctx)
	defer cancel()
	return runner.Close(teardownCtx)
}

func (p DataplaneStartPayload) infrastructureSignature() string {
	addresses := append([]string(nil), p.ProtectedAddresses...)
	sort.Strings(addresses)
	return strings.Join([]string{
		strings.TrimSpace(p.TunnelProxyEndpoint),
		strconv.Itoa(p.ProtectedPort),
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
		UDPSupported:       p.UDPSupported,
	})
	return policy, endpoint, protectedAddresses, nil
}
