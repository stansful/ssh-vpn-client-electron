package app

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"shadowssh/service/internal/dataplane"
	"shadowssh/service/internal/routing"
)

func TestDataplanePayloadCarriesTheTransportsOwnProcess(t *testing.T) {
	var payload DataplaneStartPayload
	raw := `{"routingMode":"proxy-all","tunnelProxyEndpoint":"127.0.0.1:10808","protectedAddresses":["198.51.100.4"],` +
		`"protectedPort":443,"directProcesses":[{"pid":4242,"name":"xray.exe"}],"someFutureField":true}`
	if err := decodePayload(json.RawMessage(raw), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.DirectProcesses) != 1 || payload.DirectProcesses[0] != (DirectProcessPayload{PID: 4242, Name: "xray.exe"}) {
		t.Fatalf("directProcesses = %v", payload.DirectProcesses)
	}
	policy, _, _, err := payload.compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	flow := dataplane.Flow{
		Protocol:    dataplane.ProtocolTCP,
		Destination: netip.MustParseAddrPort("203.0.113.80:443"),
		ProcessName: "Xray.exe",
		ProcessID:   4242,
	}
	if decision := policy.Decide(flow); decision.Verdict != dataplane.VerdictDirect || decision.Reason != "direct-process" {
		t.Fatalf("expected Xray's own dial to stay direct, got %+v", decision)
	}
	// Another program with the same file name is not the transport.
	other := flow
	other.ProcessID = 777
	if decision := policy.Decide(other); decision.Verdict != dataplane.VerdictProxy {
		t.Fatalf("expected another xray.exe to be tunnelled, got %+v", decision)
	}
	// A payload without the field, as the SSH bridge sends it, selects nothing
	// by process.
	payload.DirectProcesses = nil
	policy, _, _, err = payload.compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if decision := policy.Decide(flow); decision.Verdict != dataplane.VerdictProxy {
		t.Fatalf("expected proxy-all without a transport process, got %+v", decision)
	}
	// A process without an ID cannot be told apart from any other.
	payload.DirectProcesses = []DirectProcessPayload{{Name: "xray.exe"}}
	if _, _, _, err := payload.compile(); err == nil {
		t.Fatal("a transport process without a pid was accepted")
	}
}

func TestAnInvalidRuleIsSkippedWithAWarningAndTheRestStillRoutes(t *testing.T) {
	payload := hysteria2DataplanePayload("")
	payload.RoutingMode = routing.ModeSelectedRules
	payload.RoutingRules = []routing.Rule{
		{ID: "zero", Type: routing.RuleIP, Value: "10.0.0.0/08", Enabled: true},
		{ID: "net", Type: routing.RuleIP, Value: "203.0.113.0/24", Enabled: true},
	}
	policy, _, _, err := payload.compile()
	if err != nil {
		t.Fatalf("one invalid rule refused the revision: %v", err)
	}
	if decision := policy.Decide(dataplane.Flow{
		Protocol:    dataplane.ProtocolTCP,
		Destination: netip.MustParseAddrPort("203.0.113.9:443"),
	}); decision.Verdict != dataplane.VerdictProxy || decision.RuleID != "net" {
		t.Fatalf("expected the valid rule to keep selecting, got %+v", decision)
	}

	var mu sync.Mutex
	var logged []string
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(level, message string) {
		mu.Lock()
		logged = append(logged, level+": "+message)
		mu.Unlock()
	}})
	service.reportSkippedRules(payload.RoutingRules)
	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 || !strings.HasPrefix(logged[0], "warning: ") || !strings.Contains(logged[0], `ip "10.0.0.0/08"`) {
		t.Fatalf("expected one warning naming the skipped rule, got %v", logged)
	}
	if strings.Contains(logged[0], "203.0.113.0/24") {
		t.Fatalf("the valid rule was reported as skipped: %v", logged)
	}

	// A revision with nothing to skip says nothing.
	logged = nil
	service.reportSkippedRules(payload.RoutingRules[1:])
	if len(logged) != 0 {
		t.Fatalf("expected no warning, got %v", logged)
	}
}

func TestStartDataplaneRefusesSelectedRulesWithNothingValidLeft(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(string, string) {}})
	payload := hysteria2DataplanePayload("")
	payload.RoutingMode = routing.ModeSelectedRules
	payload.RoutingRules = []routing.Rule{{ID: "zero", Type: routing.RuleIP, Value: "10.0.0.0/08", Enabled: true}}
	result := service.HandleCommand(context.Background(), command("1", "start-dataplane", payload))
	if result.Response.OK || !strings.Contains(result.Response.Error, "selected-rules mode requires") {
		t.Fatalf("expected the empty selection to be refused, got %+v", result.Response)
	}
}
