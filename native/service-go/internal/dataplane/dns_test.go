package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"shadowssh/service/internal/routing"
)

// buildResponse assembles a minimal DNS response: one question, then the given
// answers, with the answer names written as compression pointers to the
// question name the way a real resolver does.
func buildResponse(question string, answers []dnsRecord) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x1234)
	message[2] = 0x81 // response, recursion desired
	message[3] = 0x80 // recursion available, RCODE 0
	binary.BigEndian.PutUint16(message[4:6], 1)
	binary.BigEndian.PutUint16(message[6:8], uint16(len(answers)))

	questionOffset := len(message)
	message = appendName(message, question)
	message = binary.BigEndian.AppendUint16(message, 1) // QTYPE A
	message = binary.BigEndian.AppendUint16(message, 1) // QCLASS IN

	for _, answer := range answers {
		message = binary.BigEndian.AppendUint16(message, uint16(0xc000|questionOffset))
		recordType := uint16(1)
		if !answer.Address.Is4() {
			recordType = 28
		}
		message = binary.BigEndian.AppendUint16(message, recordType)
		message = binary.BigEndian.AppendUint16(message, 1)
		message = binary.BigEndian.AppendUint32(message, uint32(answer.TTL/time.Second))
		raw := answer.Address.AsSlice()
		message = binary.BigEndian.AppendUint16(message, uint16(len(raw)))
		message = append(message, raw...)
	}
	return message
}

func appendName(message []byte, name string) []byte {
	start := 0
	for index := 0; index <= len(name); index++ {
		if index == len(name) || name[index] == '.' {
			message = append(message, byte(index-start))
			message = append(message, name[start:index]...)
			start = index + 1
		}
	}
	return append(message, 0)
}

func TestParseDNSAnswersReadsCompressedNames(t *testing.T) {
	address := netip.MustParseAddr("149.154.167.51")
	message := buildResponse("api.telegram.org", []dnsRecord{{Address: address, TTL: 300 * time.Second}})

	records := parseDNSAnswers(message)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if len(records[0].Names) == 0 || records[0].Names[0] != "api.telegram.org" {
		t.Fatalf("expected the question name first, got %v", records[0].Names)
	}
	if records[0].Address != address {
		t.Fatalf("expected %s, got %s", address, records[0].Address)
	}
	if records[0].TTL != 300*time.Second {
		t.Fatalf("expected the record TTL, got %s", records[0].TTL)
	}
}

func TestParseDNSAnswersBoundsTheTTL(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")
	short := parseDNSAnswers(buildResponse("example.com", []dnsRecord{{Address: address, TTL: time.Second}}))
	if len(short) != 1 || short[0].TTL != dnsMinTTL {
		t.Fatalf("expected a very short TTL to be raised to %s, got %+v", dnsMinTTL, short)
	}
	long := parseDNSAnswers(buildResponse("example.com", []dnsRecord{{Address: address, TTL: 48 * time.Hour}}))
	if len(long) != 1 || long[0].TTL != dnsMaxTTL {
		t.Fatalf("expected a very long TTL to be capped at %s, got %+v", dnsMaxTTL, long)
	}
}

func TestParseDNSAnswersRejectsQueriesAndGarbage(t *testing.T) {
	query := buildResponse("example.com", nil)
	query[2] = 0x00 // clear the response bit
	if records := parseDNSAnswers(query); records != nil {
		t.Fatalf("expected a query to yield nothing, got %+v", records)
	}
	if records := parseDNSAnswers([]byte{1, 2, 3}); records != nil {
		t.Fatalf("expected a truncated message to yield nothing, got %+v", records)
	}
	// A pointer that does not move backwards is a compression loop.
	loop := buildResponse("example.com", []dnsRecord{{Address: netip.MustParseAddr("1.2.3.4"), TTL: time.Minute}})
	answerOffset := 12 + len("example.com") + 2 + 4
	binary.BigEndian.PutUint16(loop[answerOffset:answerOffset+2], uint16(0xc000|answerOffset))
	if records := parseDNSAnswers(loop); len(records) != 0 {
		t.Fatalf("expected a compression loop to yield nothing, got %+v", records)
	}
}

func TestDomainCacheExpiresAndBounds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewDomainCache(2)
	cache.now = func() time.Time { return now }

	address := netip.MustParseAddr("93.184.216.34")
	cache.Record([]dnsRecord{{Address: address, Names: []string{"example.com"}, TTL: time.Minute}})
	if got := cache.Lookup(address); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("expected the learned name, got %v", got)
	}

	now = now.Add(2 * time.Minute)
	if got := cache.Lookup(address); got != nil {
		t.Fatalf("expected an expired entry to be unusable, got %v", got)
	}

	// The bound holds even when nothing has expired.
	cache.now = func() time.Time { return now }
	for index := 0; index < 8; index++ {
		cache.Record([]dnsRecord{{
			Address: netip.AddrFrom4([4]byte{10, 0, 0, byte(index)}),
			Names:   []string{"host.example"},
			TTL:     time.Hour,
		}})
	}
	if size := len(cache.entries); size > 2 {
		t.Fatalf("expected the cache to stay within its bound, got %d entries", size)
	}
}

func TestParseDNSAnswersKeepsBothTheQueriedNameAndTheRecordOwner(t *testing.T) {
	// A CDN answer arrives under the alias. Recording only that would lose the
	// name the application asked for, and with it every domain rule written
	// against it.
	address := netip.MustParseAddr("93.184.216.34")
	message := buildResponseWithOwner("www.example.com", "cdn.example.net", address)

	records := parseDNSAnswers(message)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if len(records[0].Names) != 2 || records[0].Names[0] != "www.example.com" || records[0].Names[1] != "cdn.example.net" {
		t.Fatalf("expected the queried name first and the owner second, got %v", records[0].Names)
	}
}

// buildResponseWithOwner writes the answer's owner name out in full instead of
// pointing back at the question, which is what a CNAME chain produces.
func buildResponseWithOwner(question string, owner string, address netip.Addr) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], 0x1234)
	message[2] = 0x81
	message[3] = 0x80
	binary.BigEndian.PutUint16(message[4:6], 1)
	binary.BigEndian.PutUint16(message[6:8], 1)

	message = appendName(message, question)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint16(message, 1)

	message = appendName(message, owner)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint32(message, 300)
	raw := address.AsSlice()
	message = binary.BigEndian.AppendUint16(message, uint16(len(raw)))
	return append(message, raw...)
}

func TestDomainCacheAccumulatesNamesPerAddress(t *testing.T) {
	cache := NewDomainCache(0)
	address := netip.MustParseAddr("203.0.113.7")
	cache.Record([]dnsRecord{{Address: address, Names: []string{"www.example.org", "cdn.example.net"}, TTL: time.Minute}})
	cache.Record([]dnsRecord{{Address: address, Names: []string{"other.test"}, TTL: time.Minute}})
	names := cache.Lookup(address)
	if len(names) != 3 || names[0] != "other.test" || names[1] != "www.example.org" || names[2] != "cdn.example.net" {
		t.Fatalf("names = %v", names)
	}
	// A repeat moves nothing and adds nothing.
	cache.Record([]dnsRecord{{Address: address, Names: []string{"www.example.org"}, TTL: time.Minute}})
	if names := cache.Lookup(address); len(names) != 3 || names[0] != "www.example.org" {
		t.Fatalf("after a repeat: %v", names)
	}
	// The list is bounded, newest first.
	for index := 0; index < 20; index++ {
		cache.Record([]dnsRecord{{Address: address, Names: []string{fmt.Sprintf("site%d.test", index)}, TTL: time.Minute}})
	}
	names = cache.Lookup(address)
	if len(names) != domainCacheMaxNames || names[0] != "site19.test" {
		t.Fatalf("bounded names = %v", names)
	}
}

// buildQuery assembles a query for name, type A, with the given ID.
func buildQuery(id uint16, name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	message[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = appendName(message, name)
	message = binary.BigEndian.AppendUint16(message, 1)
	return binary.BigEndian.AppendUint16(message, 1)
}

// answerTo is a response to query number id for name, answering address.
func answerTo(id uint16, name string, address netip.Addr) []byte {
	message := buildResponse(name, []dnsRecord{{Address: address, TTL: 300 * time.Second}})
	binary.BigEndian.PutUint16(message[0:2], id)
	return message
}

func TestDNSExchangeMatchesAnAnswerToItsQuery(t *testing.T) {
	query, ok := parseDNSExchange(buildQuery(0xbeef, "blocked.example.org"))
	if !ok || query.response {
		t.Fatalf("query not parsed: %+v", query)
	}
	matches := func(message []byte) bool {
		t.Helper()
		reply, ok := parseDNSExchange(message)
		return ok && reply.answers(query)
	}
	address := netip.MustParseAddr("192.0.2.70")
	if !matches(answerTo(0xbeef, "blocked.example.org", address)) {
		t.Fatal("the answer was not matched")
	}
	// Resolvers may echo a 0x20-randomised question in either case.
	if !matches(answerTo(0xbeef, "BLOCKED.Example.ORG", address)) {
		t.Fatal("a case-randomised echo was not matched")
	}
	if matches(answerTo(0xbeee, "blocked.example.org", address)) {
		t.Fatal("an answer with another ID was matched")
	}
	if matches(answerTo(0xbeef, "other.example.org", address)) {
		t.Fatal("an answer to another question was matched")
	}
	aaaa := answerTo(0xbeef, "blocked.example.org", address)
	binary.BigEndian.PutUint16(aaaa[12+len("blocked.example.org")+2:], 28)
	if matches(aaaa) {
		t.Fatal("an answer for another record type was matched")
	}
	if matches(buildQuery(0xbeef, "blocked.example.org")) {
		t.Fatal("a query was taken for its own answer")
	}

	// An error answer that dropped the question is matched on its ID; one
	// claiming success without the question is not.
	bare := make([]byte, 12)
	binary.BigEndian.PutUint16(bare[0:2], 0xbeef)
	bare[2] = 0x81
	bare[3] = 0x82 // SERVFAIL
	if !matches(bare) {
		t.Fatal("an error answer without the question was not matched")
	}
	bare[3] = 0x80
	if matches(bare) {
		t.Fatal("a success without the question was matched")
	}
	if _, ok := parseDNSExchange([]byte{0xbe, 0xef, 0x01}); ok {
		t.Fatal("a truncated header was parsed")
	}
}

// scriptedResolverConn is the physical side of a DNS relay: every query sent
// through it is answered with the datagrams script returns for it, in order.
type scriptedResolverConn struct {
	script    func(query []byte) []scriptedDatagram
	replies   chan scriptedDatagram
	written   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	deadline  time.Time
}

type scriptedDatagram struct {
	from    netip.AddrPort
	payload []byte
}

func newScriptedResolverConn(script func(query []byte) []scriptedDatagram) *scriptedResolverConn {
	return &scriptedResolverConn{
		script:  script,
		replies: make(chan scriptedDatagram, 64),
		written: make(chan []byte, 16),
		closed:  make(chan struct{}),
	}
}

func (c *scriptedResolverConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	query := append([]byte(nil), payload...)
	c.written <- query
	for _, datagram := range c.script(query) {
		c.replies <- datagram
	}
	return len(payload), nil
}

func (c *scriptedResolverConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var expired <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case datagram := <-c.replies:
		return copy(buffer, datagram.payload), net.UDPAddrFromAddrPort(datagram.from), nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-expired:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *scriptedResolverConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *scriptedResolverConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *scriptedResolverConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}

func (c *scriptedResolverConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *scriptedResolverConn) SetWriteDeadline(time.Time) error { return nil }

type resolverDirectDialer struct{ conn *scriptedResolverConn }

func (d resolverDirectDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("no tcp in this test")
}

func (d resolverDirectDialer) ListenUDP(context.Context, netip.AddrPort) (net.PacketConn, error) {
	return d.conn, nil
}

func TestServeDNSOnlyAcceptsTheResolversAnswerToTheQuery(t *testing.T) {
	resolver := netip.MustParseAddrPort("203.0.113.53:53")
	learned := func(octet byte) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, octet}) }
	conn := newScriptedResolverConn(func(query []byte) []scriptedDatagram {
		id := binary.BigEndian.Uint16(query[0:2])
		return []scriptedDatagram{
			// Right answer, wrong sender: anything can reach the relay's port.
			{netip.MustParseAddrPort("198.51.100.66:53"), answerTo(id, "blocked.example.org", learned(66))},
			// The resolver, but another exchange's ID.
			{resolver, answerTo(id+1, "blocked.example.org", learned(67))},
			// The resolver and the ID, but another question.
			{resolver, answerTo(id, "other.example.org", learned(68))},
			// The resolver's address from another port.
			{netip.MustParseAddrPort("203.0.113.53:5353"), answerTo(id, "blocked.example.org", learned(69))},
			// The answer.
			{resolver, answerTo(id, "Blocked.Example.org", learned(70))},
		}
	})
	adapter := newPipeAdapter()
	dialers := newRecordingDialers()
	domains := NewDomainCache(0)
	plane, err := Start(Options{
		Adapter: adapter,
		Tunnel:  dialers,
		Direct:  resolverDirectDialer{conn},
		Policy:  NewPolicy(Config{Mode: routing.ModeProxyAll}),
		Domains: domains,
		Log:     func(level, message string) { t.Logf("%s: %s", level, message) },
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	client := newClientStack(t, adapter)
	t.Cleanup(func() {
		client.close()
		_ = plane.Close()
	})

	app := client.dialUDP(t, resolver)
	defer app.Close()
	query := buildQuery(0x4d2e, "blocked.example.org")
	if _, err := app.Write(query); err != nil {
		t.Fatal(err)
	}
	select {
	case sent := <-conn.written:
		if !bytes.Equal(sent, query) {
			t.Fatal("the query was not forwarded intact")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the query was not forwarded")
	}

	reply := make([]byte, 1500)
	_ = app.SetReadDeadline(time.Now().Add(3 * time.Second))
	read, err := app.Read(reply)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if want := answerTo(0x4d2e, "Blocked.Example.org", learned(70)); !bytes.Equal(reply[:read], want) {
		t.Fatalf("the application was given the wrong datagram: %x", reply[:read])
	}
	_ = app.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if read, err := app.Read(reply); err == nil {
		t.Fatalf("a second datagram reached the application: %x", reply[:read])
	}

	if names := domains.Lookup(learned(70)); len(names) != 1 || names[0] != "blocked.example.org" {
		t.Fatalf("the answer was not learned: %v", names)
	}
	for _, octet := range []byte{66, 67, 68, 69} {
		if names := domains.Lookup(learned(octet)); names != nil {
			t.Fatalf("a datagram that was not the answer taught %s: %v", learned(octet), names)
		}
	}
}

// wireGuardInitiation is the opening datagram of a WireGuard handshake: a
// tunnel run on port 53 to get past a firewall, and nothing like DNS.
func wireGuardInitiation() []byte {
	message := make([]byte, 148)
	message[0] = 1
	for index := 4; index < len(message); index++ {
		message[index] = byte(index * 7)
	}
	return message
}

// startResolverDataplane runs a dataplane whose physical side is conn.
func startResolverDataplane(t *testing.T, cfg Config, tunnel TunnelDialer, conn *scriptedResolverConn) *clientStack {
	t.Helper()
	adapter := newPipeAdapter()
	if tunnel == nil {
		tunnel = newRecordingDialers()
	}
	plane, err := Start(Options{
		Adapter: adapter,
		Tunnel:  tunnel,
		Direct:  resolverDirectDialer{conn},
		Policy:  NewPolicy(cfg),
		Domains: NewDomainCache(0),
		Log:     func(level, message string) { t.Logf("%s: %s", level, message) },
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	client := newClientStack(t, adapter)
	t.Cleanup(func() {
		client.close()
		_ = plane.Close()
	})
	return client
}

func readReply(t *testing.T, app net.Conn) []byte {
	t.Helper()
	reply := make([]byte, 1500)
	_ = app.SetReadDeadline(time.Now().Add(3 * time.Second))
	read, err := app.Read(reply)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	return reply[:read]
}

func TestDataplaneRoutesUDPToPort53ThatIsNotDNSLikeAnyOtherFlow(t *testing.T) {
	// DNSCrypt and VPNs run on port 53 to get past firewalls. None of it reads
	// as a DNS query, and the DNS relay used to drop all of it.
	initiation := wireGuardInitiation()
	if query, ok := parseDNSExchange(initiation); ok && !query.response {
		t.Fatal("the test datagram reads as a DNS query")
	}
	server := netip.MustParseAddrPort("203.0.113.53:53")
	response := []byte("handshake response, not DNS either")

	// Unselected in split tunnel: out the physical interface, every datagram
	// and every reply, as before there was a DNS relay to drop them.
	conn := newScriptedResolverConn(func([]byte) []scriptedDatagram {
		return []scriptedDatagram{{server, response}}
	})
	client := startResolverDataplane(t, Config{Mode: routing.ModeSelectedRules, UDPSupported: true}, nil, conn)
	app := client.dialUDP(t, server)
	defer app.Close()
	if _, err := app.Write(initiation); err != nil {
		t.Fatal(err)
	}
	select {
	case sent := <-conn.written:
		if !bytes.Equal(sent, initiation) {
			t.Fatal("the datagram was not forwarded intact")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a datagram to port 53 that is not DNS was dropped")
	}
	if reply := readReply(t, app); !bytes.Equal(reply, response) {
		t.Fatalf("the application was given the wrong datagram: %q", reply)
	}

	// In full tunnel it is tunnelled like any other datagram flow.
	tunnel := newRelayTunnel(t, true)
	unused := newScriptedResolverConn(func([]byte) []scriptedDatagram { return nil })
	tunnelled := startResolverDataplane(t, Config{Mode: routing.ModeProxyAll, UDPSupported: true}, tunnel, unused)
	app = tunnelled.dialUDP(t, server)
	defer app.Close()
	if _, err := app.Write(initiation); err != nil {
		t.Fatal(err)
	}
	if reply := readReply(t, app); !bytes.Equal(reply, initiation) {
		t.Fatalf("expected the tunnel's echo, got %q", reply)
	}
	select {
	case sent := <-unused.written:
		t.Fatalf("a tunnelled flow went out the physical interface: %x", sent)
	default:
	}
}

func TestDataplaneDoesNotTakeTheTransportsOwnPort53ForDNS(t *testing.T) {
	// A transport served on port 53 is relayed in full, in both directions,
	// even when a datagram happens to read as a query: none of its replies
	// would pass as the answer to one.
	server := netip.MustParseAddrPort("203.0.113.53:53")
	response := []byte("transport traffic")
	conn := newScriptedResolverConn(func([]byte) []scriptedDatagram {
		return []scriptedDatagram{{server, response}}
	})
	client := startResolverDataplane(t, Config{
		Mode:               routing.ModeProxyAll,
		UDPSupported:       true,
		ProtectedEndpoints: []netip.AddrPort{server},
	}, nil, conn)
	app := client.dialUDP(t, server)
	defer app.Close()
	if _, err := app.Write(buildQuery(0x2a2a, "looks.like.dns.example")); err != nil {
		t.Fatal(err)
	}
	if reply := readReply(t, app); !bytes.Equal(reply, response) {
		t.Fatalf("the transport's reply was not handed back: %q", reply)
	}
}
