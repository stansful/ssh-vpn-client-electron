package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/routing"
)

type fakeDriver struct {
	applyCalls int
}

func (driver *fakeDriver) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		Target:        platform.CurrentTarget(),
		IPC:           "stdio",
		SSHCoreLinked: false,
	}
}

func (driver *fakeDriver) ApplyRouting(context.Context, platform.RoutingConfig) error {
	driver.applyCalls++
	return platform.ErrRoutingDriverNotInstalled
}

func (*fakeDriver) ClearRouting(context.Context) error {
	return nil
}

func (*fakeDriver) ListProcessConnections(context.Context) ([]platform.ProcessConnection, error) {
	return nil, platform.ErrRoutingDriverNotInstalled
}

func TestAppRejectsUnauthorizedCommand(t *testing.T) {
	service := New(Options{AuthToken: "secret", Driver: &fakeDriver{}})
	result := service.HandleCommand(context.Background(), protocol.Command{ID: "1", Type: "get-status"})
	if result.Response.OK || !strings.Contains(result.Response.Error, "unauthorized") {
		t.Fatalf("expected unauthorized response, got %+v", result.Response)
	}
}

func TestAppConnectIsFailClosedWithoutSSHCore(t *testing.T) {
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
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	result := service.HandleCommand(context.Background(), protocol.Command{ID: "1", Type: "connect", Payload: rawPayload})
	if !result.Response.OK {
		t.Fatalf("expected ok response, got %+v", result.Response)
	}
	if driver.applyCalls != 1 {
		t.Fatalf("expected routing apply call, got %d", driver.applyCalls)
	}

	status, ok := result.Response.Payload.(RuntimeStatus)
	if !ok {
		t.Fatalf("expected RuntimeStatus payload, got %T", result.Response.Payload)
	}
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

func TestAppSelectedRulesRequiresEnabledRule(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}})
	payload := ConnectPayload{
		Config:      SSHConfig{ID: "cfg", Host: "ssh.example.com", Port: 22, Username: "alice"},
		RoutingMode: routing.ModeSelectedRules,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	result := service.HandleCommand(context.Background(), protocol.Command{ID: "1", Type: "connect", Payload: rawPayload})
	if result.Response.OK || !strings.Contains(result.Response.Error, "selected-rules") {
		t.Fatalf("expected selected-rules validation error, got %+v", result.Response)
	}
}
