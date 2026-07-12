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
	mu                   sync.Mutex
	mutationMu           sync.Mutex
	authToken            string
	driver               platform.Driver
	status               RuntimeStatus
	routingMode          routing.Mode
	routingRules         []routing.Rule
	routingProxyDomains  []string
	routingDirectDomains []string
	checkEndpoint        string
	shuttingDown         bool
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
		RealTunnelAvailable: false,
	}

	return &App{
		authToken:   options.AuthToken,
		driver:      driver,
		status:      status,
		routingMode: routing.ModeSelectedRules,
	}
}

func (a *App) HandleCommand(ctx context.Context, command protocol.Command) protocol.CommandResult {
	if command.ProtocolVersion != protocol.Version {
		return protocol.CommandResult{Response: protocol.Error(command.ID, fmt.Errorf(
			"unsupported service protocol version %d; expected %d",
			command.ProtocolVersion,
			protocol.Version,
		))}
	}
	if err := a.authorize(command); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	if isStateChangingCommand(command.Type) {
		a.mutationMu.Lock()
		defer a.mutationMu.Unlock()
		if a.shuttingDown && command.Type != "shutdown" {
			return protocol.CommandResult{Response: protocol.Error(command.ID, errors.New("native service is shutting down"))}
		}
	}

	switch command.Type {
	case "get-status":
		return a.ok(command.ID, a.currentStatus())
	case "get-capabilities":
		return a.ok(command.ID, map[string]any{
			"protocolVersion": protocol.Version,
			"capabilities":    a.driver.Capabilities(),
		})
	case "connect":
		return a.handleConnect(ctx, command)
	case "disconnect":
		return a.handleDisconnect(ctx, command)
	case "check-tunnel":
		return a.handleCheckTunnel(command)
	case "open-terminal":
		return a.handleOpenTerminal(command)
	case "close-terminal":
		return a.ok(command.ID, protocol.Accepted(), diagnostic("info", "Native shell channel close requested."))
	case "terminal-input":
		return a.handleTerminalInput(command)
	case "update-config":
		return a.handleUpdateConfig(command)
	case "update-routing-rules":
		return a.handleUpdateRoutingRules(command)
	case "update-routing":
		return a.handleUpdateRouting(command)
	case "list-process-connections":
		return a.handleListProcessConnections(ctx, command)
	case "shutdown":
		return a.handleShutdown(command)
	default:
		return protocol.CommandResult{Response: protocol.Error(command.ID, fmt.Errorf("unsupported service command %q", command.Type))}
	}
}

func (a *App) Shutdown(ctx context.Context) error {
	a.mutationMu.Lock()
	defer a.mutationMu.Unlock()
	if err := a.clearRoutingAndSetDisconnected(ctx, "Native service stopped."); err != nil {
		a.setRoutingCleanupError(err)
		return err
	}
	a.shuttingDown = true
	return nil
}

func (a *App) handleListProcessConnections(ctx context.Context, command protocol.Command) protocol.CommandResult {
	connections, err := a.driver.ListProcessConnections(ctx)
	if err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	return a.ok(command.ID, map[string]any{"connections": connections})
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

	// Routing must be the final step of a successful tunnel transaction. This
	// binary has no live SSH engine, so fail closed and only clear stale routes.
	routingErr := a.clearRouting(ctx)

	a.mu.Lock()
	a.routingMode = payload.RoutingMode
	a.routingRules = append([]routing.Rule(nil), payload.RoutingRules...)
	a.routingProxyDomains = append([]string(nil), payload.RoutingProxyDomains...)
	a.routingDirectDomains = append([]string(nil), payload.RoutingDirectDomains...)
	a.checkEndpoint = payload.CheckEndpoint
	a.status.State = "Error"
	a.status.ActiveConfigID = payload.Config.ID
	a.status.Message = "Native service refused to report a connected tunnel because the live SSH engine is not linked into this binary yet."
	a.status.RealTunnelAvailable = false
	status := a.status
	a.mu.Unlock()

	events := []any{
		statusChanged(status),
		diagnostic("error", "Native service reached routing/platform boundary, but live SSH/direct-tcpip/shell engine is unavailable in this binary."),
	}
	if routingErr != nil {
		events = append(events, diagnostic("warning", "Unable to clear stale routing after failed connect: "+routingErr.Error()))
	}

	return protocol.CommandResult{
		Response: protocol.Error(command.ID, errors.New("native live SSH tunnel engine is unavailable")),
		Events:   events,
	}
}

func (a *App) handleDisconnect(ctx context.Context, command protocol.Command) protocol.CommandResult {
	if err := a.clearRoutingAndSetDisconnected(ctx, "Disconnected."); err != nil {
		status := a.setRoutingCleanupError(err)
		return protocol.CommandResult{
			Response: protocol.Error(command.ID, fmt.Errorf("clear routing: %w", err)),
			Events:   []any{statusChanged(status), diagnostic("error", "Routing cleanup failed: "+err.Error())},
		}
	}

	status := a.currentStatus()
	return a.ok(command.ID, status, statusChanged(status), diagnostic("info", "Tunnel state cleared."))
}

func (a *App) handleShutdown(command protocol.Command) protocol.CommandResult {
	if err := a.clearRoutingAndSetDisconnected(context.Background(), "Native service stopped."); err != nil {
		status := a.setRoutingCleanupError(err)
		return protocol.CommandResult{
			Response: protocol.Error(command.ID, fmt.Errorf("clear routing before shutdown: %w", err)),
			Events:   []any{statusChanged(status), diagnostic("error", "Native service shutdown refused because routing cleanup failed: "+err.Error())},
		}
	}
	a.shuttingDown = true
	result := a.ok(command.ID, protocol.Accepted(), statusChanged(a.currentStatus()), diagnostic("info", "Native service shutdown requested."))
	result.Shutdown = true
	return result
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
	if len(payload.Endpoint) > 2048 {
		return protocol.CommandResult{Response: protocol.Error(command.ID, errors.New("endpoint is too long"))}
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
	return protocol.CommandResult{
		Response: protocol.Error(command.ID, errors.New("native SSH shell engine is unavailable")),
		Events:   []any{terminalOutput(line)},
	}
}

func (a *App) handleTerminalInput(command protocol.Command) protocol.CommandResult {
	var payload struct {
		Input string `json:"input"`
	}
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	return protocol.CommandResult{
		Response: protocol.Error(command.ID, errors.New("native SSH shell engine is unavailable")),
		Events:   []any{diagnostic("warning", "Terminal input was rejected because no live SSH shell channel is active.")},
	}
}

func (a *App) handleUpdateConfig(command protocol.Command) protocol.CommandResult {
	var payload struct {
		Config SSHConfig `json:"config"`
	}
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	if strings.TrimSpace(payload.Config.ID) == "" {
		return protocol.CommandResult{Response: protocol.Error(command.ID, errors.New("config id is required"))}
	}
	return a.ok(command.ID, protocol.Accepted())
}

func (a *App) handleUpdateRoutingRules(command protocol.Command) protocol.CommandResult {
	var payload struct {
		Rules []routing.Rule `json:"rules"`
	}
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	a.mu.Lock()
	mode := a.routingMode
	proxyDomains := append([]string(nil), a.routingProxyDomains...)
	a.mu.Unlock()
	if err := validateRouting(mode, payload.Rules, proxyDomains); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	a.mu.Lock()
	a.routingRules = append([]routing.Rule(nil), payload.Rules...)
	a.mu.Unlock()

	matcher := routing.NewMatcher(mode, payload.Rules)
	summary := matcher.Summary()

	message := fmt.Sprintf("Service routing rules updated: enabled=%d domains=%d ips=%d processes=%d invalid=%d.",
		summary.EnabledRules,
		summary.DomainRules,
		summary.IPRules,
		summary.ProcessRules,
		summary.InvalidRules,
	)
	return a.ok(command.ID, protocol.Accepted(), diagnostic("info", message))
}

func (a *App) handleUpdateRouting(command protocol.Command) protocol.CommandResult {
	var payload RoutingUpdatePayload
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	if err := validateRouting(payload.RoutingMode, payload.RoutingRules, payload.RoutingProxyDomains); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	a.mu.Lock()
	a.routingMode = payload.RoutingMode
	a.routingRules = append([]routing.Rule(nil), payload.RoutingRules...)
	a.routingProxyDomains = append([]string(nil), payload.RoutingProxyDomains...)
	a.routingDirectDomains = append([]string(nil), payload.RoutingDirectDomains...)
	a.checkEndpoint = payload.CheckEndpoint
	a.mu.Unlock()

	summary := routing.NewMatcher(payload.RoutingMode, payload.RoutingRules).Summary()
	message := fmt.Sprintf(
		"Service routing updated: mode=%s enabled=%d domains=%d ips=%d processes=%d invalid=%d proxyListDomains=%d directListDomains=%d.",
		payload.RoutingMode,
		summary.EnabledRules,
		summary.DomainRules,
		summary.IPRules,
		summary.ProcessRules,
		summary.InvalidRules,
		len(payload.RoutingProxyDomains),
		len(payload.RoutingDirectDomains),
	)
	return a.ok(command.ID, protocol.Accepted(), diagnostic("info", message))
}

func (a *App) clearRouting(ctx context.Context) error {
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	return a.driver.ClearRouting(cleanupCtx)
}

func (a *App) clearRoutingAndSetDisconnected(ctx context.Context, message string) error {
	if err := a.clearRouting(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	a.status.State = "Disconnected"
	a.status.ActiveConfigID = ""
	a.status.Message = message
	a.status.ConnectedAt = ""
	a.status.RealTunnelAvailable = false
	a.mu.Unlock()
	return nil
}

func (a *App) setRoutingCleanupError(err error) RuntimeStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.State = "Error"
	a.status.Message = "Routing cleanup failed: " + err.Error()
	a.status.RealTunnelAvailable = false
	return a.status
}

func cleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	// Route rollback must outlive a canceled request/service context, but remains
	// bounded so shutdown cannot hang forever.
	_ = parent
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func isStateChangingCommand(commandType string) bool {
	switch commandType {
	case "connect", "disconnect", "open-terminal", "close-terminal", "terminal-input", "update-config", "update-routing-rules", "update-routing", "shutdown":
		return true
	default:
		return false
	}
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
	return validateRouting(payload.RoutingMode, payload.RoutingRules, payload.RoutingProxyDomains)
}

func validateRouting(mode routing.Mode, rules []routing.Rule, proxyDomains []string) error {
	if mode != routing.ModeProxyAll && mode != routing.ModeSelectedRules {
		return fmt.Errorf("unsupported routing mode %q", mode)
	}
	if mode != routing.ModeSelectedRules {
		return nil
	}
	// Count compiled rules, not merely enabled records. An enabled malformed IP
	// or unknown rule type must not satisfy selected routing and silently turn
	// into DIRECT-all behavior at the platform boundary.
	if routing.NewMatcher(mode, rules).Summary().EnabledRules > 0 {
		return nil
	}
	for _, domain := range proxyDomains {
		if routing.ValidProxyDomain(domain) {
			return nil
		}
	}
	return errors.New("selected-rules mode requires at least one enabled routing rule or proxy-list domain")
}
