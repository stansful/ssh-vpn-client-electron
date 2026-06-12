package platform

import (
	"context"
	"errors"
)

var (
	ErrUnsupportedPlatform       = errors.New("platform driver is unavailable on this OS")
	ErrRoutingDriverNotInstalled = errors.New("routing driver is not installed")
)

type Target struct {
	Platform                  string `json:"platform"`
	Arch                      string `json:"arch"`
	ServiceExecutableName     string `json:"serviceExecutableName"`
	ServiceRelativePath       string `json:"serviceRelativePath"`
	SupportsPrivilegedService bool   `json:"supportsPrivilegedService"`
}

type Capabilities struct {
	Target                       Target `json:"target"`
	IPC                          string `json:"ipc"`
	NamedPipeACL                 bool   `json:"namedPipeAcl"`
	UnixSocketMode               bool   `json:"unixSocketMode"`
	ServiceControlManager        bool   `json:"serviceControlManager"`
	WFPInterception              bool   `json:"wfpInterception"`
	TUNDevice                    bool   `json:"tunDevice"`
	RouteManipulation            bool   `json:"routeManipulation"`
	ProcessConnectionAttribution bool   `json:"processConnectionAttribution"`
	DNSVisibility                bool   `json:"dnsVisibility"`
	IPv6RouteEnforcement         bool   `json:"ipv6RouteEnforcement"`
	UDPForwarding                bool   `json:"udpForwarding"`
	SSHCoreLinked                bool   `json:"sshCoreLinked"`
}

type RoutingRule struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Enabled bool   `json:"enabled"`
}

type RoutingConfig struct {
	Mode              string        `json:"mode"`
	Rules             []RoutingRule `json:"rules"`
	ProtectedHost     string        `json:"protectedHost,omitempty"`
	ProtectedPort     int           `json:"protectedPort,omitempty"`
	EnforceIPv4       bool          `json:"enforceIpv4"`
	EnforceIPv6       bool          `json:"enforceIpv6"`
	AllowUDP          bool          `json:"allowUdp"`
	LoopPreventionPID int           `json:"loopPreventionPid,omitempty"`
}

type ProcessConnection struct {
	PID           int    `json:"pid"`
	ProcessName   string `json:"processName"`
	LocalAddress  string `json:"localAddress"`
	LocalPort     int    `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    int    `json:"remotePort"`
	Protocol      string `json:"protocol"`
}

type Driver interface {
	Capabilities() Capabilities
	ApplyRouting(ctx context.Context, config RoutingConfig) error
	ClearRouting(ctx context.Context) error
	ListProcessConnections(ctx context.Context) ([]ProcessConnection, error)
}
