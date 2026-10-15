package dataplane

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"shadowssh/service/internal/routing"
)

// relayTunnel is a transport whose server takes UDP through one relay. A
// silent one never answers: the association succeeds, as it always does on
// Xray, and the datagrams go nowhere. An echoing one sends each back.
type relayTunnel struct {
	t         *testing.T
	relayPort uint16
	received  chan []byte
}

func newRelayTunnel(t *testing.T, echo bool) *relayTunnel {
	t.Helper()
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { relay.Close() })
	tunnel := &relayTunnel{t: t, relayPort: uint16(relay.LocalAddr().(*net.UDPAddr).Port), received: make(chan []byte, 256)}
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			read, from, err := relay.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if payload, _, ok := decodeSocksUDPDatagram(buffer[:read]); ok {
				tunnel.received <- append([]byte(nil), payload...)
			}
			if echo {
				_, _ = relay.WriteToUDP(buffer[:read], from)
			}
		}
	}()
	return tunnel
}

func newSilentRelayTunnel(t *testing.T) *relayTunnel {
	return newRelayTunnel(t, false)
}

func (r *relayTunnel) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, net.ErrClosed
}

// AssociateUDP opens each association on a SOCKS endpoint of its own: the
// fake accepts one connection, and a flow per destination needs one each.
func (r *relayTunnel) AssociateUDP(ctx context.Context) (*Socks5UDPSession, error) {
	endpoint, _ := startFakeSocks5(r.t, func(byte, netip.AddrPort) (byte, netip.AddrPort) {
		return socksReplySucceeded, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.relayPort)
	})
	return (&Socks5Client{Endpoint: endpoint}).AssociateUDP(ctx)
}

// drain waits for count datagrams to reach the relay.
func (r *relayTunnel) drain(count int) {
	r.t.Helper()
	for i := 0; i < count; i++ {
		select {
		case <-r.received:
		case <-time.After(3 * time.Second):
			r.t.Fatalf("only %d of %d datagrams reached the relay", i, count)
		}
	}
}

func shortenUnansweredAge(t *testing.T) {
	previous := udpUnansweredWarnAge
	udpUnansweredWarnAge = 0
	t.Cleanup(func() { udpUnansweredWarnAge = previous })
}

func countLines(logged []string, fragment string) int {
	count := 0
	for _, line := range logged {
		if strings.Contains(line, fragment) {
			count++
		}
	}
	return count
}

func startDataplaneWithTunnel(t *testing.T, cfg Config, tunnel TunnelDialer) (*clientStack, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var logged []string
	adapter := newPipeAdapter()
	dialers := newRecordingDialers()
	dataplane, err := Start(Options{
		Adapter: adapter,
		Tunnel:  tunnel,
		Direct:  testDirectDialer{dialers},
		Policy:  NewPolicy(cfg),
		Log: func(level, message string) {
			mu.Lock()
			logged = append(logged, level+": "+message)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	client := newClientStack(t, adapter)
	t.Cleanup(func() {
		client.close()
		_ = dataplane.Close()
	})
	return client, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), logged...)
	}
}

func waitForLine(t *testing.T, logged func() []string, fragment string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range logged() {
			if strings.Contains(line, fragment) {
				return line
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no log line with %q; got %v", fragment, logged())
	return ""
}

func TestDataplaneReportsTunnelledUDPThatIsNeverAnswered(t *testing.T) {
	// With Xray the association always succeeds, so a server that does not
	// pass UDP - or a call whose media goes nowhere - shows up only as a flow
	// that is never answered. Before this, nothing at all was logged.
	shortenUnansweredAge(t)
	tunnel := newSilentRelayTunnel(t)
	client, logged := startDataplaneWithTunnel(t, Config{Mode: routing.ModeProxyAll, UDPSupported: true}, tunnel)
	send := func(destination string) {
		t.Helper()
		conn := client.dialUDP(t, netip.MustParseAddrPort(destination))
		t.Cleanup(func() { conn.Close() })
		for i := 0; i < udpUnansweredWarnAfter; i++ {
			if _, err := conn.Write([]byte("stun binding request")); err != nil {
				t.Fatal(err)
			}
		}
		tunnel.drain(udpUnansweredWarnAfter)
	}
	send("142.250.82.10:19305")
	line := waitForLine(t, logged, "no reply")
	if !strings.HasPrefix(line, "warning: ") || !strings.Contains(line, "142.250.82.10:19305") {
		t.Fatalf("unexpected line %q", line)
	}
	// Another flow to the same address does not repeat it; one to another
	// address does.
	send("142.250.82.10:19306")
	send("142.250.82.11:19305")
	waitForLine(t, logged, "142.250.82.11:19305")
	time.Sleep(50 * time.Millisecond)
	if count := countLines(logged(), "no reply"); count != 2 {
		t.Fatalf("expected one warning per address, got %d: %v", count, logged())
	}
}

func TestDataplaneDoesNotReportAnAnsweredFlow(t *testing.T) {
	shortenUnansweredAge(t)
	tunnel := newRelayTunnel(t, true)
	client, logged := startDataplaneWithTunnel(t, Config{Mode: routing.ModeProxyAll, UDPSupported: true}, tunnel)
	conn := client.dialUDP(t, netip.MustParseAddrPort("142.250.82.10:19305"))
	defer conn.Close()
	// Ping-pong, so every reply is back before the next datagram goes.
	reply := make([]byte, 64)
	for i := 0; i < 2*udpUnansweredWarnAfter; i++ {
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if read, err := conn.Read(reply); err != nil || string(reply[:read]) != "ping" {
			t.Fatalf("echo %d: %q, %v", i, reply[:read], err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if count := countLines(logged(), "no reply"); count != 0 {
		t.Fatalf("an answered flow was reported: %v", logged())
	}
}

func TestDataplaneWaitsBeforeReportingAnUnansweredFlow(t *testing.T) {
	// Twenty datagrams can go out before the first reply of a new
	// association is possible; time is what tells silence apart.
	tunnel := newSilentRelayTunnel(t)
	client, logged := startDataplaneWithTunnel(t, Config{Mode: routing.ModeProxyAll, UDPSupported: true}, tunnel)
	conn := client.dialUDP(t, netip.MustParseAddrPort("142.250.82.10:19305"))
	defer conn.Close()
	for i := 0; i < 2*udpUnansweredWarnAfter; i++ {
		if _, err := conn.Write([]byte("tick")); err != nil {
			t.Fatal(err)
		}
	}
	tunnel.drain(2 * udpUnansweredWarnAfter)
	time.Sleep(50 * time.Millisecond)
	if count := countLines(logged(), "no reply"); count != 0 {
		t.Fatalf("a burst was reported before %v had passed: %v", udpUnansweredWarnAge, logged())
	}
}

func TestLogLimiterLetsOneLineThroughPerInterval(t *testing.T) {
	var limiter logLimiter
	start := time.Unix(1_000_000, 0)
	if !limiter.allow("a", start) {
		t.Fatal("the first line was held back")
	}
	if limiter.allow("a", start.Add(udpWarningInterval-time.Second)) {
		t.Fatal("a repeat inside the interval got through")
	}
	if !limiter.allow("b", start) {
		t.Fatal("another key was held back")
	}
	if !limiter.allow("a", start.Add(udpWarningInterval)) {
		t.Fatal("a line after the interval was held back")
	}
}

func TestLogLimiterStaysBounded(t *testing.T) {
	var limiter logLimiter
	start := time.Unix(1_000_000, 0)
	for i := 0; i < logLimiterMaxKeys; i++ {
		limiter.allow(fmt.Sprintf("key %d", i), start)
	}
	// Full of fresh keys: the map is reset rather than grown.
	if !limiter.allow("one more", start) || len(limiter.last) > logLimiterMaxKeys {
		t.Fatalf("the limiter grew to %d keys", len(limiter.last))
	}
	// Full of stale keys: they are pruned, and recent ones are kept.
	limiter = logLimiter{}
	for i := 0; i < logLimiterMaxKeys-1; i++ {
		limiter.allow(fmt.Sprintf("stale %d", i), start)
	}
	limiter.allow("recent", start.Add(udpWarningInterval))
	if !limiter.allow("new", start.Add(udpWarningInterval)) {
		t.Fatal("a new key was held back")
	}
	if limiter.allow("recent", start.Add(udpWarningInterval+time.Second)) {
		t.Fatal("pruning dropped a key that is still inside its interval")
	}
	if len(limiter.last) > 2 {
		t.Fatalf("stale keys were kept: %d", len(limiter.last))
	}
}

func TestDataplaneKeepsATunnelledUDPFlowAfterAnOversizedDatagram(t *testing.T) {
	tunnel := newSilentRelayTunnel(t)
	client, logged := startDataplaneWithTunnel(t, Config{Mode: routing.ModeProxyAll, UDPSupported: true}, tunnel)
	conn := client.dialUDP(t, netip.MustParseAddrPort("198.51.100.20:5000"))
	defer conn.Close()
	// Larger than the client's MTU as well: it arrives fragmented and is
	// reassembled by the stack before the dataplane sees it.
	if _, err := conn.Write(make([]byte, 9000)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-tunnel.received:
		if string(payload) != "after" {
			t.Fatalf("the relay received %d bytes first, expected the small datagram", len(payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the flow did not survive an oversized datagram")
	}
	waitForLine(t, logged, "dropped a 9000-byte datagram")
}
