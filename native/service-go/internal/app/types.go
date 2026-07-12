package app

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/routing"
)

type RuntimeStatus struct {
	State               string          `json:"state"`
	ActiveConfigID      string          `json:"activeConfigId,omitempty"`
	Message             string          `json:"message"`
	ConnectedAt         string          `json:"connectedAt,omitempty"`
	ReconnectAttempt    int             `json:"reconnectAttempt"`
	Transport           string          `json:"transport"`
	PlatformTarget      platform.Target `json:"platformTarget"`
	RealTunnelAvailable bool            `json:"realTunnelAvailable"`
}

type SSHConfig struct {
	ID                           string `json:"id"`
	Name                         string `json:"name"`
	Host                         string `json:"host"`
	Port                         int    `json:"port"`
	Username                     string `json:"username"`
	AuthType                     string `json:"authType"`
	PasswordSecretID             string `json:"passwordSecretId,omitempty"`
	PrivateKeyID                 string `json:"privateKeyId,omitempty"`
	PrivateKeyPassphraseSecretID string `json:"privateKeyPassphraseSecretId,omitempty"`
	ExpectedServerFingerprint    string `json:"expectedServerFingerprint"`
	KeepaliveIntervalSec         int    `json:"keepaliveIntervalSec"`
	Note                         string `json:"note"`
	CreatedAt                    string `json:"createdAt"`
	UpdatedAt                    string `json:"updatedAt"`
}

type ConnectPayload struct {
	Config               SSHConfig         `json:"config"`
	RoutingMode          routing.Mode      `json:"routingMode"`
	RoutingRules         []routing.Rule    `json:"routingRules"`
	RoutingProxyDomains  []string          `json:"routingProxyDomains"`
	RoutingDirectDomains []string          `json:"routingDirectDomains"`
	CheckEndpoint        string            `json:"checkEndpoint"`
	Secrets              map[string]string `json:"secrets,omitempty"`
}

type RoutingUpdatePayload struct {
	RoutingMode          routing.Mode   `json:"routingMode"`
	RoutingRules         []routing.Rule `json:"routingRules"`
	RoutingProxyDomains  []string       `json:"routingProxyDomains"`
	RoutingDirectDomains []string       `json:"routingDirectDomains"`
	CheckEndpoint        string         `json:"checkEndpoint"`
}

type DiagnosticsEntry struct {
	ID      string `json:"id"`
	At      string `json:"at"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type TerminalLine struct {
	ID     string `json:"id"`
	At     string `json:"at"`
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

type TunnelCheckResult struct {
	Endpoint string `json:"endpoint"`
	OK       bool   `json:"ok"`
	At       string `json:"at"`
	Message  string `json:"message"`
}

type statusChangedEvent struct {
	Type   string        `json:"type"`
	Status RuntimeStatus `json:"status"`
}

type diagnosticEvent struct {
	Type  string           `json:"type"`
	Entry DiagnosticsEntry `json:"entry"`
}

type terminalOutputEvent struct {
	Type string       `json:"type"`
	Line TerminalLine `json:"line"`
}

type tunnelCheckEvent struct {
	Type   string            `json:"type"`
	Result TunnelCheckResult `json:"result"`
}

func statusChanged(status RuntimeStatus) statusChangedEvent {
	return statusChangedEvent{Type: "status-changed", Status: status}
}

func diagnostic(level string, message string) diagnosticEvent {
	return diagnosticEvent{
		Type: "diagnostics-appended",
		Entry: DiagnosticsEntry{
			ID:      newEventID(),
			At:      time.Now().UTC().Format(time.RFC3339Nano),
			Level:   level,
			Message: message,
		},
	}
}

func terminalOutput(line TerminalLine) terminalOutputEvent {
	return terminalOutputEvent{Type: "terminal-output", Line: line}
}

func tunnelCheck(result TunnelCheckResult) tunnelCheckEvent {
	return tunnelCheckEvent{Type: "tunnel-check-result", Result: result}
}

func newEventID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return hex.EncodeToString(bytes[:])
}
