package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/routing"
)

type fakeDriver struct {
	applyCalls  atomic.Int32
	clearCalls  atomic.Int32
	activeClear atomic.Int32
	maxClear    atomic.Int32
	canceledCtx atomic.Bool
	clearErr    error
	clearBlock  <-chan struct{}
	clearEnter  chan<- struct{}
}

func (driver *fakeDriver) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		Target:        platform.CurrentTarget(),
		IPC:           "stdio",
		SSHCoreLinked: false,
	}
}

func (driver *fakeDriver) ApplyRouting(context.Context, platform.RoutingConfig) error {
	driver.applyCalls.Add(1)
	return platform.ErrRoutingDriverNotInstalled
}

func (driver *fakeDriver) ClearRouting(ctx context.Context) error {
	driver.clearCalls.Add(1)
	if ctx.Err() != nil {
		driver.canceledCtx.Store(true)
	}
	active := driver.activeClear.Add(1)
	defer driver.activeClear.Add(-1)
	for {
		maximum := driver.maxClear.Load()
		if active <= maximum || driver.maxClear.CompareAndSwap(maximum, active) {
			break
		}
	}
	if driver.clearEnter != nil {
		select {
		case driver.clearEnter <- struct{}{}:
		default:
		}
	}
	if driver.clearBlock != nil {
		<-driver.clearBlock
	}
	return driver.clearErr
}

func (*fakeDriver) ListProcessConnections(context.Context) ([]platform.ProcessConnection, error) {
	return []platform.ProcessConnection{{PID: 42, ProcessName: "chrome.exe", RemoteAddress: "1.1.1.1", RemotePort: 443, Protocol: "tcp4"}}, nil
}

func TestAppRejectsUnsupportedProtocolVersion(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), protocol.Command{ProtocolVersion: protocol.Version + 1, ID: "1", Type: "get-status"})
	if result.Response.OK || !strings.Contains(result.Response.Error, "protocol version") {
		t.Fatalf("expected protocol version error, got %+v", result.Response)
	}
}

func TestAppReportsFailClosedCapabilities(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), command("1", "get-capabilities", nil))
	if !result.Response.OK {
		t.Fatalf("expected capabilities response, got %+v", result.Response)
	}
	payload, ok := result.Response.Payload.(map[string]any)
	if !ok || payload["protocolVersion"] != protocol.Version {
		t.Fatalf("unexpected capabilities payload: %#v", result.Response.Payload)
	}
	capabilities, ok := payload["capabilities"].(platform.Capabilities)
	if !ok || capabilities.SSHCoreLinked || capabilities.WFPInterception || capabilities.TUNDevice || capabilities.RouteManipulation || capabilities.UDPForwarding {
		t.Fatalf("native stub advertised unavailable dataplane capabilities: %+v", capabilities)
	}
}

func TestAppRejectsUnauthorizedCommandAndDoesNotRequestShutdown(t *testing.T) {
	service := New(Options{AuthToken: "secret", Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), command("1", "shutdown", nil))
	if result.Response.OK || !strings.Contains(result.Response.Error, "unauthorized") {
		t.Fatalf("expected unauthorized response, got %+v", result.Response)
	}
	if result.Shutdown {
		t.Fatal("unauthorized command requested service shutdown")
	}
}

func TestAppConnectIsFailClosedWithoutApplyingRouting(t *testing.T) {
	driver := &fakeDriver{}
	service := New(Options{Driver: driver})
	payload := ConnectPayload{
		Config: SSHConfig{
			ID:       "cfg",
			Host:     "ssh.example.com",
			Port:     22,
			Username: "alice",
		},
		RoutingMode: routing.ModeSelectedRules,
		RoutingRules: []routing.Rule{
			{ID: "rule", Type: routing.RuleDomain, Value: "example.com", Enabled: true},
		},
		Secrets: map[string]string{"password": "do-not-log"},
	}

	result := service.HandleCommand(context.Background(), command("1", "connect", payload))
	if result.Response.OK || !strings.Contains(result.Response.Error, "unavailable") {
		t.Fatalf("expected unavailable error response, got %+v", result.Response)
	}
	if driver.applyCalls.Load() != 0 {
		t.Fatalf("routing was applied without a tunnel: %d calls", driver.applyCalls.Load())
	}
	if driver.clearCalls.Load() != 1 {
		t.Fatalf("expected stale routing cleanup, got %d calls", driver.clearCalls.Load())
	}
	status := service.currentStatus()
	if status.State != "Error" || status.RealTunnelAvailable {
		t.Fatalf("expected fail-closed unavailable tunnel status, got %+v", status)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "do-not-log") {
		t.Fatalf("secret leaked into command result: %s", string(encoded))
	}
}

func TestAppShellCommandsRemainFailClosedWithoutSSHCore(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	opened := service.HandleCommand(context.Background(), command("1", "open-terminal", nil))
	if opened.Response.OK || !strings.Contains(opened.Response.Error, "unavailable") {
		t.Fatalf("open-terminal pretended a shell was available: %+v", opened.Response)
	}
	input := service.HandleCommand(context.Background(), command("2", "terminal-input", map[string]string{"input": "whoami\n"}))
	if input.Response.OK || !strings.Contains(input.Response.Error, "unavailable") {
		t.Fatalf("terminal-input pretended a shell was available: %+v", input.Response)
	}
}

func TestAppBoundsTunnelCheckEndpoint(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), command("1", "check-tunnel", map[string]string{
		"endpoint": strings.Repeat("x", 2049),
	}))
	if result.Response.OK || !strings.Contains(result.Response.Error, "too long") {
		t.Fatalf("oversized tunnel-check endpoint was accepted: %+v", result.Response)
	}
}

func TestAppSelectedRulesAcceptsProxyListDomain(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	payload := ConnectPayload{
		Config:              SSHConfig{ID: "cfg", Host: "ssh.example.com", Port: 22, Username: "alice"},
		RoutingMode:         routing.ModeSelectedRules,
		RoutingProxyDomains: []string{"example.com"},
	}

	result := service.HandleCommand(context.Background(), command("1", "connect", payload))
	if result.Response.OK || strings.Contains(result.Response.Error, "selected-rules") {
		t.Fatalf("proxy-list domain should satisfy selected routing validation: %+v", result.Response)
	}
}

func TestAppSelectedRulesRequiresEnabledTarget(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	payload := ConnectPayload{
		Config:      SSHConfig{ID: "cfg", Host: "ssh.example.com", Port: 22, Username: "alice"},
		RoutingMode: routing.ModeSelectedRules,
	}

	result := service.HandleCommand(context.Background(), command("1", "connect", payload))
	if result.Response.OK || !strings.Contains(result.Response.Error, "selected-rules") {
		t.Fatalf("expected selected-rules validation error, got %+v", result.Response)
	}
}

func TestAppSelectedRulesRejectsEnabledButInvalidTarget(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	payload := ConnectPayload{
		Config:      SSHConfig{ID: "cfg", Host: "ssh.example.com", Port: 22, Username: "alice"},
		RoutingMode: routing.ModeSelectedRules,
		RoutingRules: []routing.Rule{
			{ID: "invalid", Type: routing.RuleIP, Value: "not-an-ip", Enabled: true},
		},
	}

	result := service.HandleCommand(context.Background(), command("1", "connect", payload))
	if result.Response.OK || !strings.Contains(result.Response.Error, "selected-rules") {
		t.Fatalf("enabled invalid target must not satisfy selected routing: %+v", result.Response)
	}
}

func TestAppSelectedRulesRejectsInvalidProxyListDomain(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	payload := ConnectPayload{
		Config:              SSHConfig{ID: "cfg", Host: "ssh.example.com", Port: 22, Username: "alice"},
		RoutingMode:         routing.ModeSelectedRules,
		RoutingProxyDomains: []string{"bad domain"},
	}

	result := service.HandleCommand(context.Background(), command("1", "connect", payload))
	if result.Response.OK || !strings.Contains(result.Response.Error, "selected-rules") {
		t.Fatalf("invalid proxy-list domain must not satisfy selected routing: %+v", result.Response)
	}
}

func TestAppUpdateRoutingStoresCompleteContract(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	payload := RoutingUpdatePayload{
		RoutingMode:          routing.ModeSelectedRules,
		RoutingRules:         []routing.Rule{{ID: "rule", Type: routing.RuleDomain, Value: "example.com", Enabled: true}},
		RoutingProxyDomains:  []string{"proxy.example"},
		RoutingDirectDomains: []string{"direct.example"},
		CheckEndpoint:        "example.com:443",
	}
	result := service.HandleCommand(context.Background(), command("1", "update-routing", payload))
	if !result.Response.OK {
		t.Fatalf("expected update-routing success, got %+v", result.Response)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.routingMode != payload.RoutingMode || len(service.routingProxyDomains) != 1 || len(service.routingDirectDomains) != 1 || service.checkEndpoint != payload.CheckEndpoint {
		t.Fatalf("routing contract was not stored: mode=%s proxy=%v direct=%v endpoint=%q", service.routingMode, service.routingProxyDomains, service.routingDirectDomains, service.checkEndpoint)
	}
}

func TestAppDisconnectAndShutdownRequireRoutingCleanup(t *testing.T) {
	driver := &fakeDriver{}
	service := New(Options{Driver: driver})
	disconnect := service.HandleCommand(context.Background(), command("1", "disconnect", nil))
	if !disconnect.Response.OK {
		t.Fatalf("disconnect failed: %+v", disconnect.Response)
	}
	shutdown := service.HandleCommand(context.Background(), command("2", "shutdown", nil))
	if !shutdown.Response.OK || !shutdown.Shutdown {
		t.Fatalf("authorized clean shutdown was not requested: %+v", shutdown)
	}
	if driver.clearCalls.Load() != 2 {
		t.Fatalf("expected two routing cleanup calls, got %d", driver.clearCalls.Load())
	}

	driver.clearErr = errors.New("driver busy")
	failed := service.HandleCommand(context.Background(), command("3", "shutdown", nil))
	if failed.Response.OK || failed.Shutdown {
		t.Fatalf("shutdown must fail closed when routing cleanup fails: %+v", failed)
	}
}

func TestAppShutdownCleansRoutingAfterParentContextCancellation(t *testing.T) {
	driver := &fakeDriver{}
	service := New(Options{Driver: driver})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatalf("cleanup with canceled parent failed: %v", err)
	}
	if driver.clearCalls.Load() != 1 || driver.canceledCtx.Load() {
		t.Fatalf("routing cleanup inherited canceled context: calls=%d canceled=%v", driver.clearCalls.Load(), driver.canceledCtx.Load())
	}
}

func TestAppRejectsStateChangesAfterSuccessfulShutdown(t *testing.T) {
	driver := &fakeDriver{}
	service := New(Options{Driver: driver})
	shutdown := service.HandleCommand(context.Background(), command("1", "shutdown", nil))
	if !shutdown.Response.OK || !shutdown.Shutdown {
		t.Fatalf("expected successful shutdown, got %+v", shutdown)
	}

	disconnect := service.HandleCommand(context.Background(), command("2", "disconnect", nil))
	if disconnect.Response.OK || !strings.Contains(disconnect.Response.Error, "shutting down") {
		t.Fatalf("state change was accepted after shutdown: %+v", disconnect)
	}
	if driver.clearCalls.Load() != 1 {
		t.Fatalf("post-shutdown command performed another routing mutation: %d", driver.clearCalls.Load())
	}
}

func TestAppSerializesStateChangingCommands(t *testing.T) {
	block := make(chan struct{})
	entered := make(chan struct{}, 2)
	driver := &fakeDriver{clearBlock: block, clearEnter: entered}
	service := New(Options{Driver: driver})
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			service.HandleCommand(context.Background(), command(id, "disconnect", nil))
		}(string(rune('1' + index)))
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first state-changing command did not enter driver")
	}
	time.Sleep(25 * time.Millisecond)
	if driver.maxClear.Load() != 1 || driver.clearCalls.Load() != 1 {
		t.Fatalf("state-changing commands overlapped: max=%d calls=%d", driver.maxClear.Load(), driver.clearCalls.Load())
	}
	close(block)
	wg.Wait()
	if driver.clearCalls.Load() != 2 || driver.maxClear.Load() != 1 {
		t.Fatalf("unexpected serialized cleanup counts: max=%d calls=%d", driver.maxClear.Load(), driver.clearCalls.Load())
	}
}

func TestAppListsProcessConnections(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), command("1", "list-process-connections", nil))
	if !result.Response.OK {
		t.Fatalf("expected ok response, got %+v", result.Response)
	}

	payload, ok := result.Response.Payload.(map[string]any)
	if !ok {
		t.Fatalf("expected map payload, got %T", result.Response.Payload)
	}
	connections, ok := payload["connections"].([]platform.ProcessConnection)
	if !ok || len(connections) != 1 || connections[0].ProcessName != "chrome.exe" {
		t.Fatalf("unexpected connections payload: %#v", payload["connections"])
	}
}

func command(id string, commandType string, payload any) protocol.Command {
	var rawPayload json.RawMessage
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			panic(err)
		}
		rawPayload = encoded
	}
	return protocol.Command{ProtocolVersion: protocol.Version, ID: id, Type: commandType, Payload: rawPayload}
}
