package app

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"shadowssh/service/internal/dataplane"
	"shadowssh/service/internal/routing"
)

func hysteria2DataplanePayload(protectedPorts string) DataplaneStartPayload {
	return DataplaneStartPayload{
		RoutingMode:         routing.ModeProxyAll,
		TunnelProxyEndpoint: "127.0.0.1:10808",
		ProtectedAddresses:  []string{"198.51.100.4"},
		ProtectedPort:       443,
		ProtectedPorts:      protectedPorts,
		UDPSupported:        true,
		EnforceIPv6:         true,
		AdapterName:         "Shadow SSH",
		JournalPath:         "routes.journal",
	}
}

func TestDataplanePayloadProtectsHopPorts(t *testing.T) {
	policy, _, addresses, err := hysteria2DataplanePayload(" 443, 20000 - 30000 ").compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	want := []dataplane.PortRange{{First: 443, Last: 443}, {First: 20000, Last: 30000}}
	if got := policy.Config().ProtectedPorts; !reflect.DeepEqual(got, want) {
		t.Fatalf("protected ports = %+v, want %+v", got, want)
	}
	// The host route is still planned for the address alone, whatever the ports.
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("198.51.100.4") {
		t.Fatalf("unexpected protected addresses: %v", addresses)
	}

	hop := policy.Decide(dataplane.Flow{Protocol: dataplane.ProtocolUDP, Destination: netip.MustParseAddrPort("198.51.100.4:25000")})
	if hop.Verdict != dataplane.VerdictDirect || hop.Reason != "protected-ssh-connection" {
		t.Fatalf("expected a hop port to stay direct, got %+v", hop)
	}
	outside := policy.Decide(dataplane.Flow{Protocol: dataplane.ProtocolUDP, Destination: netip.MustParseAddrPort("198.51.100.4:30001")})
	if outside.Verdict != dataplane.VerdictProxy {
		t.Fatalf("expected a port outside the list to be routed normally, got %+v", outside)
	}
}

func TestDataplanePayloadReadsPortListsLikeTheLinkParser(t *testing.T) {
	cases := map[string][]dataplane.PortRange{
		"":            nil,
		"   ":         nil,
		"443":         {{First: 443, Last: 443}},
		"30000-20000": {{First: 20000, Last: 30000}},
		"1-65535":     {{First: 1, Last: 65535}},
		"443,8443,20000-30000": {
			{First: 443, Last: 443},
			{First: 8443, Last: 8443},
			{First: 20000, Last: 30000},
		},
	}
	for list, want := range cases {
		got, err := parsePortList(list)
		if err != nil {
			t.Fatalf("parsePortList(%q): %v", list, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parsePortList(%q) = %+v, want %+v", list, got, want)
		}
	}
}

func TestDataplanePayloadRejectsMalformedProtectedPorts(t *testing.T) {
	for _, list := range []string{
		"0",
		"65536",
		"443,",
		",443",
		"443,,8443",
		"20000-",
		"-30000",
		"1-2-3",
		"443;8443",
		"443 8443",
		"+443",
		"0x1bb",
		"https",
		"20000-70000",
	} {
		if _, _, _, err := hysteria2DataplanePayload(list).compile(); err == nil || !strings.Contains(err.Error(), "protectedPorts") {
			t.Fatalf("expected %q to be refused with a protectedPorts error, got %v", list, err)
		}
	}
}

func TestStartDataplaneRefusesMalformedProtectedPortsBeforeStarting(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), command("1", "start-dataplane", hysteria2DataplanePayload("443,20000-")))
	if result.Response.OK || !strings.Contains(result.Response.Error, `protectedPorts contains "20000-"`) {
		t.Fatalf("expected the start request to be refused, got %+v", result.Response)
	}
	service.dataplaneMu.Lock()
	defer service.dataplaneMu.Unlock()
	if service.dataplane != nil || service.dataplaneSignature != "" {
		t.Fatal("a refused start request left dataplane state behind")
	}
}

func TestDataplaneSignatureTracksProtectedPorts(t *testing.T) {
	hopping := hysteria2DataplanePayload("443,20000-30000")
	if hopping.infrastructureSignature() != hysteria2DataplanePayload(" 443,20000-30000 ").infrastructureSignature() {
		t.Fatal("surrounding spaces changed the signature")
	}
	// A different hop list is a different server profile, so the running
	// dataplane is rebuilt rather than handed a new policy.
	for _, other := range []string{"", "443,20000-30001", "443"} {
		if hopping.infrastructureSignature() == hysteria2DataplanePayload(other).infrastructureSignature() {
			t.Fatalf("protectedPorts %q did not change the signature", other)
		}
	}
	// A routing edit alone is still a policy swap.
	edited := hopping
	edited.RoutingMode = routing.ModeSelectedRules
	edited.RoutingProxyDomains = []string{"example.com"}
	if hopping.infrastructureSignature() != edited.infrastructureSignature() {
		t.Fatal("a routing-only change altered the signature")
	}
}
