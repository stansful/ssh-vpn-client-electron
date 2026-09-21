package dataplane

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"shadowssh/service/internal/routing"
)

// clientHelloFor captures the ClientHello Go's TLS client sends for name.
func clientHelloFor(t *testing.T, name string, versions ...uint16) []byte {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	config := &tls.Config{ServerName: name, InsecureSkipVerify: true}
	if len(versions) > 0 {
		config.MinVersion = versions[0]
		config.MaxVersion = versions[0]
	}
	client := tls.Client(clientSide, config)
	go func() {
		_ = client.Handshake()
		_ = client.Close()
	}()
	buffer := make([]byte, 64*1024)
	_ = serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	read, err := serverSide.Read(buffer)
	if err != nil || read == 0 {
		t.Fatalf("no ClientHello captured: %v", err)
	}
	return append([]byte(nil), buffer[:read]...)
}

func TestSniffClientHelloServerName(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		hello := clientHelloFor(t, "www.Example.ORG", version)
		name, needMore := sniffClientName(hello)
		if name != "www.example.org" || needMore {
			t.Fatalf("version %x: got %q needMore=%v", version, name, needMore)
		}
		// Every prefix either asks for more or already knows the name; none
		// gives up on a hello that does carry one.
		for cut := 1; cut < len(hello); cut++ {
			partial, more := sniffClientName(hello[:cut])
			if partial == "" && !more {
				t.Fatalf("version %x: gave up at %d of %d bytes", version, cut, len(hello))
			}
			if partial != "" && partial != "www.example.org" {
				t.Fatalf("version %x: wrong name %q at %d bytes", version, partial, cut)
			}
		}
	}
}

func TestSniffClientHelloSplitAcrossRecords(t *testing.T) {
	hello := clientHelloFor(t, "split.example.net", tls.VersionTLS13)
	// Re-frame the single handshake record as two records.
	length := int(binary.BigEndian.Uint16(hello[3:5]))
	handshake := hello[5 : 5+length]
	first, second := handshake[:40], handshake[40:]
	record := func(fragment []byte) []byte {
		header := []byte{0x16, 0x03, 0x01, 0, 0}
		binary.BigEndian.PutUint16(header[3:5], uint16(len(fragment)))
		return append(header, fragment...)
	}
	framed := append(record(first), record(second)...)
	name, needMore := sniffClientName(framed)
	if name != "split.example.net" || needMore {
		t.Fatalf("got %q needMore=%v", name, needMore)
	}
	// Only the first record so far: more is needed, not a verdict.
	name, needMore = sniffClientName(record(first))
	if name != "" || !needMore {
		t.Fatalf("first record alone: got %q needMore=%v", name, needMore)
	}
}

func TestSniffClientHelloWithoutServerName(t *testing.T) {
	hello := clientHelloFor(t, "", tls.VersionTLS12)
	name, needMore := sniffClientName(hello)
	if name != "" || needMore {
		t.Fatalf("got %q needMore=%v", name, needMore)
	}
	// A name that is an address literal is not a name.
	hello = clientHelloFor(t, "203.0.113.5", tls.VersionTLS12)
	if name, _ := sniffClientName(hello); name != "" {
		t.Fatalf("address literal reported as name %q", name)
	}
}

func TestSniffRejectsOtherProtocols(t *testing.T) {
	cases := [][]byte{
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		{0x00, 0x01, 0x02, 0x03},
		[]byte("220 mail.example.org ESMTP\r\n"),
		{0x16, 0x02, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5},             // SSL 2/other version byte
		{0x16, 0x03, 0x01, 0x00, 0x08, 0x02, 0, 0, 4, 1, 2, 3, 4}, // ServerHello, not ClientHello
	}
	for _, data := range cases {
		if name, needMore := sniffClientName(data); name != "" || needMore {
			t.Fatalf("%q: got %q needMore=%v", data, name, needMore)
		}
	}
	// A single byte that could start a TLS record or an HTTP method asks for more.
	for _, data := range [][]byte{{0x16}, []byte("G"), []byte("POS")} {
		if name, needMore := sniffClientName(data); name != "" || !needMore {
			t.Fatalf("%q: got %q needMore=%v", data, name, needMore)
		}
	}
}

func TestSniffHTTPHost(t *testing.T) {
	request := []byte("GET /index.html HTTP/1.1\r\nUser-Agent: test\r\nHost: Example.org:8080\r\nAccept: */*\r\n\r\nbody")
	name, needMore := sniffClientName(request)
	if name != "example.org" || needMore {
		t.Fatalf("got %q needMore=%v", name, needMore)
	}
	for cut := 1; cut < len(request); cut++ {
		partial, more := sniffClientName(request[:cut])
		if partial == "" && !more {
			t.Fatalf("gave up at %d bytes: %q", cut, request[:cut])
		}
	}
	// Absolute-form target without a Host header.
	proxyStyle := []byte("GET http://cdn.example.com/a HTTP/1.1\r\nAccept: */*\r\n\r\n")
	if name, _ := sniffClientName(proxyStyle); name != "cdn.example.com" {
		t.Fatalf("absolute form: got %q", name)
	}
	// No Host at all: a verdict, not a wait.
	bare := []byte("GET / HTTP/1.0\r\n\r\n")
	if name, more := sniffClientName(bare); name != "" || more {
		t.Fatalf("bare request: got %q needMore=%v", name, more)
	}
	// A Host carrying an address is not a name; a single label is not one a rule could match.
	for _, host := range []string{"192.168.1.10", "[::1]:80", "localhost", "intranet"} {
		data := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
		if name, _ := sniffClientName(data); name != "" {
			t.Fatalf("host %q reported as name %q", host, name)
		}
	}
}

func TestSniffTCPReadsHeadAndForwardsIt(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	hello := clientHelloFor(t, "flow.example.org", tls.VersionTLS13)
	go func() {
		// Deliver in two segments to exercise the read loop.
		_, _ = client.Write(hello[:30])
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write(hello[30:])
	}()
	head, name := sniffTCP(server)
	if name != "flow.example.org" {
		t.Fatalf("got name %q", name)
	}
	if !bytes.Equal(head, hello) {
		t.Fatalf("head differs from what was sent: %d vs %d bytes", len(head), len(hello))
	}
}

func TestSniffTCPGivesUpOnSilence(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	started := time.Now()
	head, name := sniffTCP(server)
	elapsed := time.Since(started)
	if name != "" || len(head) != 0 {
		t.Fatalf("got %q with %d bytes", name, len(head))
	}
	if elapsed < sniffTimeout/2 || elapsed > sniffTimeout*4 {
		t.Fatalf("waited %v, expected about %v", elapsed, sniffTimeout)
	}
	// The deadline must not linger on the connection afterwards.
	go func() {
		time.Sleep(2 * sniffTimeout)
		_, _ = client.Write([]byte("late"))
	}()
	buffer := make([]byte, 8)
	read, err := server.Read(buffer)
	if err != nil || string(buffer[:read]) != "late" {
		t.Fatalf("read after sniff: %q %v", buffer[:read], err)
	}
}

func TestSniffTCPStopsAtNonNameProtocol(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write([]byte("SSH-2.0-client\r\n"))
	}()
	started := time.Now()
	head, name := sniffTCP(server)
	if name != "" || string(head) != "SSH-2.0-client\r\n" {
		t.Fatalf("got %q / %q", name, head)
	}
	if time.Since(started) > sniffTimeout/2 {
		t.Fatalf("held a non-TLS flow for %v", time.Since(started))
	}
}

func TestPolicyNamesMatter(t *testing.T) {
	domainRule := routing.Rule{ID: "d", Type: routing.RuleDomain, Value: "example.org", Enabled: true}
	processRule := routing.Rule{ID: "p", Type: routing.RuleProcessName, Value: "app.exe", Enabled: true}
	cases := []struct {
		name   string
		config Config
		want   bool
	}{
		{"proxy-all", Config{Mode: routing.ModeProxyAll, Rules: []routing.Rule{domainRule}}, false},
		{"domain rule", Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{domainRule}}, true},
		{"process rule only", Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{processRule}}, false},
		{"proxy list only", Config{Mode: routing.ModeSelectedRules, ProxyDomains: []string{"ua"}}, true},
		{"direct list only", Config{Mode: routing.ModeSelectedRules, Rules: []routing.Rule{processRule}, DirectDomains: []string{"bank.example"}}, false},
	}
	for _, c := range cases {
		if got := NewPolicy(c.config).NamesMatter(); got != c.want {
			t.Fatalf("%s: NamesMatter=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestSniffedNameSelectsFlowAndTeachesCache(t *testing.T) {
	policy := NewPolicy(Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{{ID: "d", Type: routing.RuleDomain, Value: "example.org", Enabled: true}},
	})
	destination := netip.MustParseAddrPort("203.0.113.7:443")
	flow := Flow{Protocol: ProtocolTCP, Destination: destination}
	if decision := policy.Decide(flow); decision.Verdict != VerdictDirect {
		t.Fatalf("address-only flow: %v", decision)
	}
	flow.Domains = []string{"www.example.org"}
	if decision := policy.Decide(flow); decision.Verdict != VerdictProxy || decision.Reason != "domain" {
		t.Fatalf("named flow: %+v", decision)
	}
	cache := NewDomainCache(0)
	cache.Record([]dnsRecord{{Address: destination.Addr(), Names: []string{"www.example.org"}, TTL: sniffedNameTTL}})
	if names := cache.Lookup(destination.Addr()); len(names) != 1 || names[0] != "www.example.org" {
		t.Fatalf("cache did not keep the sniffed name: %v", names)
	}
	// A QUIC attempt to the same address is now recognised and, on a transport
	// without UDP, refused rather than leaked.
	udp := Flow{Protocol: ProtocolUDP, Destination: destination, Domains: cache.Lookup(destination.Addr())}
	if decision := policy.Decide(udp); decision.Verdict != VerdictDrop {
		t.Fatalf("udp to a sniffed address: %+v", decision)
	}
}

// buildClientHello synthesises a ClientHello record whose server_name
// extension comes after `padding` bytes of other extensions, the way a client
// that shuffles its extension order or sends a large key share may place it.
func buildClientHello(serverName string, padding int) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0)                      // no session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // null compression
	var extensions []byte
	for padding > 0 {
		size := min(padding, 1000)
		extensions = append(extensions, 0xfa, 0xfa, byte(size>>8), byte(size)) // a GREASE-like type
		extensions = append(extensions, make([]byte, size)...)
		padding -= size
	}
	name := []byte(serverName)
	sni := []byte{0x00, 0x00, byte((len(name) + 5) >> 8), byte(len(name) + 5), byte((len(name) + 3) >> 8), byte(len(name) + 3), 0x00, byte(len(name) >> 8), byte(len(name))}
	sni = append(sni, name...)
	extensions = append(extensions, sni...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func TestSniffClientHelloWithLateServerName(t *testing.T) {
	for _, padding := range []int{0, 300, 5000, 12000} {
		hello := buildClientHello("late.example.org", padding)
		name, needMore := sniffClientName(hello)
		if name != "late.example.org" || needMore {
			t.Fatalf("padding %d: got %q needMore=%v", padding, name, needMore)
		}
		// Delivered in 4 KiB reads, as sniffTCP sees it, no prefix gives up early.
		for cut := 4096; cut < len(hello); cut += 4096 {
			partial, more := sniffClientName(hello[:cut])
			if partial == "" && !more {
				t.Fatalf("padding %d: gave up at %d of %d bytes", padding, cut, len(hello))
			}
		}
	}
	// Beyond one TLS record's worth of hello, the sniffer stops asking.
	if name, needMore := sniffClientName(buildClientHello("x.example.org", 17000)[:sniffMaxBytes]); name != "" || needMore {
		t.Fatalf("oversized hello: got %q needMore=%v", name, needMore)
	}
}
