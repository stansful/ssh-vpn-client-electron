package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// farEnd decides what the server behind the transport does for one address.
type farEnd func(destination netip.AddrPort, server net.Conn)

// probeTunnel stands in for a transport whose server reaches some addresses.
type probeTunnel struct {
	mu     sync.Mutex
	asked  []netip.AddrPort
	hellos [][]byte
	// refuse is the SSH transport: the server could not open the connection.
	refuse func(destination netip.AddrPort) bool
	serve  farEnd
}

func (p *probeTunnel) DialTCP(ctx context.Context, destination netip.AddrPort, name string) (net.Conn, error) {
	if name != "" {
		// The probe asks about addresses; a name would let the far end pick
		// another one.
		return nil, errors.New("the probe dialled by name")
	}
	p.mu.Lock()
	p.asked = append(p.asked, destination)
	p.mu.Unlock()
	if p.refuse != nil && p.refuse(destination) {
		return nil, errors.New("proxy refused request (reply 0x1)")
	}
	ours, theirs := net.Pipe()
	go p.serve(destination, theirs)
	return ours, nil
}

func (p *probeTunnel) AssociateUDP(context.Context) (*Socks5UDPSession, error) {
	return nil, errors.New("not used")
}

func isIPv6(destination netip.AddrPort) bool { return destination.Addr().Is6() }

// closesSilently is Xray reaching nothing: its SOCKS inbound has already
// reported success, so the failure is a connection that ends without a byte.
func closesSilently(_ netip.AddrPort, server net.Conn) {
	defer server.Close()
	_, _ = server.Read(make([]byte, 4096))
}

// answers is a TLS server, as far as a reachability check can tell: whatever
// comes back after the ClientHello proves the address was reached.
func (p *probeTunnel) answers(_ netip.AddrPort, server net.Conn) {
	defer server.Close()
	hello := make([]byte, 4096)
	read, _ := server.Read(hello)
	p.mu.Lock()
	p.hellos = append(p.hellos, hello[:read])
	p.mu.Unlock()
	// A fatal handshake_failure alert.
	_, _ = server.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	_, _ = io.Copy(io.Discard, server)
}

func TestProbeTunnelIPv6IsReachableWhenEveryIPv6TargetAnswers(t *testing.T) {
	tunnel := &probeTunnel{}
	tunnel.serve = tunnel.answers
	if got := ProbeTunnelIPv6(context.Background(), tunnel); got != IPv6Reachable {
		t.Fatalf("expected reachable, got %v", got)
	}
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	for _, hello := range tunnel.hellos {
		// A server that sniffs TLS and routes by name would otherwise answer
		// for an address it cannot reach.
		for _, target := range []string{"one.one.one.one", "dns.google", "cloudflare"} {
			if strings.Contains(string(hello), target) {
				t.Fatalf("the probe's hello names %q", target)
			}
		}
	}
}

func TestProbeTunnelIPv6IsUnreachableWhenOnlyIPv4Answers(t *testing.T) {
	// The SSH transport on a server without IPv6.
	tunnel := &probeTunnel{refuse: isIPv6}
	tunnel.serve = tunnel.answers
	if got := ProbeTunnelIPv6(context.Background(), tunnel); got != IPv6Unreachable {
		t.Fatalf("expected unreachable, got %v", got)
	}
}

func TestProbeTunnelIPv6NeedsAnAnswerNotJustAConnect(t *testing.T) {
	// Xray on a server without IPv6: every CONNECT succeeds, the IPv6 ones
	// close without a byte.
	tunnel := &probeTunnel{}
	tunnel.serve = func(destination netip.AddrPort, server net.Conn) {
		if isIPv6(destination) {
			closesSilently(destination, server)
			return
		}
		tunnel.answers(destination, server)
	}
	started := time.Now()
	if got := ProbeTunnelIPv6(context.Background(), tunnel); got != IPv6Unreachable {
		t.Fatalf("expected unreachable, got %v", got)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a closed connection held the probe for %v", elapsed)
	}
}

func TestProbeTunnelIPv6NeedsEveryIPv6Target(t *testing.T) {
	// A server reaching one operator's IPv6 some other way - a WARP route for
	// Google, say - does not have IPv6 for everything else.
	tunnel := &probeTunnel{refuse: func(destination netip.AddrPort) bool { return destination == ipv6ProbeTargets[0] }}
	tunnel.serve = tunnel.answers
	if got := ProbeTunnelIPv6(context.Background(), tunnel); got != IPv6Unreachable {
		t.Fatalf("expected unreachable, got %v", got)
	}
}

func TestProbeTunnelIPv6LearnsNothingFromADeadTunnel(t *testing.T) {
	tunnel := &probeTunnel{refuse: func(netip.AddrPort) bool { return true }}
	if got := ProbeTunnelIPv6(context.Background(), tunnel); got != IPv6Unknown {
		t.Fatalf("expected unknown, got %v", got)
	}
}

func TestProbeTunnelIPv6GivesUpWithTheContext(t *testing.T) {
	// A far end that never answers must not hold the probe - or Close - past
	// its caller.
	tunnel := &probeTunnel{serve: func(_ netip.AddrPort, server net.Conn) {
		_, _ = io.Copy(io.Discard, server)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	started := time.Now()
	if got := ProbeTunnelIPv6(ctx, tunnel); got != IPv6Unknown {
		t.Fatalf("expected unknown, got %v", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the probe outlived its context by %v", elapsed)
	}
}

// watchedDataplane runs a dataplane whose probe answers from a script.
func watchedDataplane(t *testing.T, script []IPv6Reach) (*Dataplane, func() []string) {
	t.Helper()
	previousRetry, previousRecheck := ipv6ProbeRetry, ipv6ProbeRecheck
	ipv6ProbeRetry, ipv6ProbeRecheck = time.Millisecond, time.Millisecond
	t.Cleanup(func() { ipv6ProbeRetry, ipv6ProbeRecheck = previousRetry, previousRecheck })

	var mu sync.Mutex
	var logged []string
	answers := make(chan IPv6Reach, len(script))
	for _, answer := range script {
		answers <- answer
	}
	dialers := newRecordingDialers()
	dataplane, err := Start(Options{
		Adapter: newPipeAdapter(),
		Tunnel:  dialers,
		Direct:  testDirectDialer{dialers},
		Policy:  NewPolicy(Config{Mode: "proxy-all"}),
		TunnelIPv6Probe: func(ctx context.Context) IPv6Reach {
			select {
			case answer := <-answers:
				return answer
			case <-ctx.Done():
				return IPv6Unknown
			}
		},
		Log: func(level, message string) {
			mu.Lock()
			logged = append(logged, level)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	t.Cleanup(func() { _ = dataplane.Close() })
	deadline := time.Now().Add(3 * time.Second)
	for len(answers) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// The last answer is taken; let the watcher act on it.
	time.Sleep(50 * time.Millisecond)
	return dataplane, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), logged...)
	}
}

func TestTunnelIPv6WatcherWaitsForASecondYes(t *testing.T) {
	dataplane, _ := watchedDataplane(t, []IPv6Reach{IPv6Reachable})
	if dataplane.TunnelReachesIPv6() {
		t.Fatal("a single 'reachable' was trusted")
	}
}

func TestTunnelIPv6WatcherFollowsSettledAnswers(t *testing.T) {
	dataplane, logged := watchedDataplane(t, []IPv6Reach{
		IPv6Reachable, IPv6Unknown, IPv6Reachable, // confirmed across a dead moment
		IPv6Reachable, // unchanged: not logged again
		IPv6Unreachable,
	})
	if dataplane.TunnelReachesIPv6() {
		t.Fatal("'unreachable' left IPv6 enabled")
	}
	if got := logged(); len(got) != 2 || got[0] != "info" || got[1] != "warning" {
		t.Fatalf("expected one line per change, got %v", got)
	}
}

func TestTunnelIPv6WatcherKeepsTheLastAnswerWhenItLearnsNothing(t *testing.T) {
	dataplane, logged := watchedDataplane(t, []IPv6Reach{IPv6Reachable, IPv6Reachable, IPv6Unknown, IPv6Unknown})
	if !dataplane.TunnelReachesIPv6() {
		t.Fatal("a dead moment of the tunnel disabled IPv6")
	}
	if got := logged(); len(got) != 1 {
		t.Fatalf("expected one line, got %v", got)
	}
}

func TestDataplaneCloseDoesNotWaitForTheProbeSchedule(t *testing.T) {
	dialers := newRecordingDialers()
	probed := make(chan struct{}, 1)
	dataplane, err := Start(Options{
		Adapter: newPipeAdapter(),
		Tunnel:  dialers,
		Direct:  testDirectDialer{dialers},
		Policy:  NewPolicy(Config{Mode: "proxy-all"}),
		TunnelIPv6Probe: func(context.Context) IPv6Reach {
			probed <- struct{}{}
			return IPv6Unreachable
		},
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	<-probed
	closed := make(chan struct{})
	go func() {
		_ = dataplane.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for the next probe, an hour away")
	}
}
