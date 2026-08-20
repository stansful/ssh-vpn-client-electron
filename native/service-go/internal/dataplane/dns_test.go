package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
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
