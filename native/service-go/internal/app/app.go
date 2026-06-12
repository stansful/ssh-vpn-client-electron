package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/routing"
)

type Options struct {
	AuthToken string
	Driver    platform.Driver
	Transport string
}

type App struct {
	mu           sync.Mutex
	authToken    string
	driver       platform.Driver
	status       RuntimeStatus
	routingMode  routing.Mode
	routingRules []routing.Rule
}

func New(options Options) *App {
	driver := options.Driver
	if driver == nil {
		driver = platform.NewDriver()
	}

	transport := options.Transport
	if transport == "" {
		transport = "native-ipc"
	}

	status := RuntimeStatus{
		State:               "Disconnected",
		Message:             "Native service is running. SSH tunnel engine is not linked yet.",
		ReconnectAttempt:    0,
		Transport:           transport,
		PlatformTarget:      driver.Capabilities().Target,
		RealTunnelAvailable: driver.Capabilities().SSHCoreLinked,
	}

	return &App{
		authToken:   options.AuthToken,
		driver:      driver,
		status:      status,
		routingMode: routing.ModeSelectedRules,
	}
}

func (a *App) HandleCommand(ctx context.Context, command protocol.Command) protocol.CommandResult {
	if err := a.authorize(command); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	switch command.Type {
	case "get-status":
		return a.ok(command.ID, a.currentStatus())
	case "connect":
		return a.handleConnect(ctx, command)
	case "disconnect":
		return a.handleDisconnect(ctx, command)
	case "check-tunnel":
		return a.handleCheckTunnel(command)
	case "open-terminal":
		return a.handleOpenTerminal(command)
	case "terminal-input":
		return a.handleTerminalInput(command)
	case "update-config":
		return a.ok(command.ID, protocol.Accepted())
	case "update-routing-rules":
		return a.handleUpdateRoutingRules(command)
	case "shutdown":
		return a.ok(command.ID, protocol.Accepted(), diagnostic("info", "Native service shutdown requested."))
	default:
		return protocol.CommandResult{Response: protocol.Error(command.ID, fmt.Errorf("unsupported service command %q", command.Type))}
	}
}

func (a *App) authorize(command protocol.Command) error {
	if a.authToken == "" {
		return nil
	}
	if command.AuthToken != a.authToken {
		return errors.New("unauthorized service command")
	}
	return nil
}

func (a *App) currentStatus() RuntimeStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

func (a *App) handleConnect(ctx context.Context, command protocol.Command) protocol.CommandResult {
	var payload ConnectPayload
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	if err := validateConnectPayload(payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	routeRules := make([]platform.RoutingRule, 0, len(payload.RoutingRules))
	for _, rule := range payload.RoutingRules {
		routeRules = append(routeRules, platform.RoutingRule{
			ID:      rule.ID,
			Type:    string(rule.Type),
			Value:   rule.Value,
			Enabled: rule.Enabled,
		})
	}

	routingErr := a.driver.ApplyRouting(ctx, platform.RoutingConfig{
		Mode:          string(payload.RoutingMode),
		Rules:         routeRules,
		ProtectedHost: payload.Config.Host,
		ProtectedPort: payload.Config.Port,
		EnforceIPv4:   true,
		EnforceIPv6:   true,
		AllowUDP:      false,
	})

	a.mu.Lock()
	a.routingMode = payload.RoutingMode
	a.routingRules = payload.RoutingRules
	a.status.State = "Error"
	a.status.ActiveConfigID = payload.Config.ID
	a.status.Message = "Native service refused to report a connected tunnel because the live SSH engine is not linked into this binary yet."
	a.status.RealTunnelAvailable = a.driver.Capabilities().SSHCoreLinked
	status := a.status
	a.mu.Unlock()

	events := []any{
		statusChanged(status),
		diagnostic("error", "Native service reached routing/platform boundary, but live SSH/direct-tcpip/shell engine is unavailable in this binary."),
	}
	if routingErr != nil {
		events = append(events, diagnostic("warning", "Routing driver did not apply OS interception: "+routingErr.Error()))
	}

	return a.ok(command.ID, status, events...)
}

func (a *App) handleDisconnect(ctx context.Context, command protocol.Command) protocol.CommandResult {
	_ = a.driver.ClearRouting(ctx)

	a.mu.Lock()
	a.status.State = "Disconnected"
	a.status.ActiveConfigID = ""
	a.status.Message = "Disconnected."
	a.status.ConnectedAt = ""
	status := a.status
	a.mu.Unlock()

	return a.ok(command.ID, status, statusChanged(status), diagnostic("info", "Tunnel state cleared."))
}

func (a *App) handleCheckTunnel(command protocol.Command) protocol.CommandResult {
	var payload struct {
		Endpoint string `json:"endpoint"`
	}
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	if strings.TrimSpace(payload.Endpoint) == "" {
		return protocol.CommandResult{Response: protocol.Error(command.ID, errors.New("endpoint is required"))}
	}

	result := TunnelCheckResult{
		Endpoint: payload.Endpoint,
		OK:       false,
		At:       time.Now().UTC().Format(time.RFC3339Nano),
		Message:  "SSH direct-tcpip check is unavailable until the native live SSH engine is linked.",
	}
	return a.ok(command.ID, result, tunnelCheck(result))
}

func (a *App) handleOpenTerminal(command protocol.Command) protocol.CommandResult {
	line := TerminalLine{
		ID:     newEventID(),
		At:     time.Now().UTC().Format(time.RFC3339Nano),
		Stream: "system",
		Text:   "Native shell channel is unavailable until the live SSH engine is linked.\n",
	}
	return a.ok(command.ID, protocol.Accepted(), terminalOutput(line))
}

func (a *App) handleTerminalInput(command protocol.Command) protocol.CommandResult {
	var payload struct {
		Input string `json:"input"`
	}
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	return a.ok(command.ID, protocol.Accepted(), diagnostic("warning", "Terminal input was rejected because no live SSH shell channel is active."))
}

func (a *App) handleUpdateRoutingRules(command protocol.Command) protocol.CommandResult {
	var payload struct {
		Rules []routing.Rule `json:"rules"`
	}
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	matcher := routing.NewMatcher(a.routingMode, payload.Rules)
	summary := matcher.Summary()

	a.mu.Lock()
	a.routingRules = payload.Rules
	a.mu.Unlock()

	message := fmt.Sprintf("Service routing rules updated: enabled=%d domains=%d ips=%d processes=%d invalid=%d.",
		summary.EnabledRules,
		summary.DomainRules,
		summary.IPRules,
		summary.ProcessRules,
		summary.InvalidRules,
	)
	return a.ok(command.ID, protocol.Accepted(), diagnostic("info", message))
}

func (a *App) ok(id string, payload any, events ...any) protocol.CommandResult {
	return protocol.CommandResult{Response: protocol.OK(id, payload), Events: events}
}

func decodePayload(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		return errors.New("payload is required")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	return nil
}

func validateConnectPayload(payload ConnectPayload) error {
	if strings.TrimSpace(payload.Config.ID) == "" {
		return errors.New("config id is required")
	}
	if strings.TrimSpace(payload.Config.Host) == "" {
		return errors.New("config host is required")
	}
	if payload.Config.Port < 1 || payload.Config.Port > 65535 {
		return errors.New("config port must be between 1 and 65535")
	}
	if strings.TrimSpace(payload.Config.Username) == "" {
		return errors.New("config username is required")
	}
	if payload.RoutingMode == routing.ModeSelectedRules {
		hasEnabled := false
		for _, rule := range payload.RoutingRules {
			if rule.Enabled {
				hasEnabled = true
				break
			}
		}
		if !hasEnabled {
			return errors.New("selected-rules mode requires at least one enabled routing rule")
		}
	}
	return nil
}
