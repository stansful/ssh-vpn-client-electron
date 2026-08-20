package dataplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Once the TUN adapter owns the default route, name resolution runs through
// this package or it does not run at all. Two things are needed from it:
// answers must keep flowing, and the address an application is about to
// connect to must be traceable back to the name it asked for, because a domain
// rule and the curated proxy list are expressed in names while a packet only
// carries an address.
//
// The queries themselves are forwarded to the resolver the machine already
// used, out through the physical interface. Sending them through the tunnel is
// not an option on the SSH transport, which has no datagram channel, and doing
// it only for selected processes would need the answer before the flow that
// reveals the process. The cost is that DNS is visible to the local resolver
// exactly as it was before the tunnel came up; the routing of the connection
// that follows is not.

const (
	// dnsMaxMessageBytes bounds a single parsed message. 64 KiB is the largest
	// a TCP-framed DNS message can be.
	dnsMaxMessageBytes = 64 * 1024
	// dnsMaxNameLabels stops a malformed message from walking a compression
	// loop. A legal name has at most 127 labels.
	dnsMaxNameLabels = 128
	// dnsMinTTL keeps a very short-lived answer usable for at least as long as
	// it takes the application to open the connection it resolved for.
	dnsMinTTL = 10 * time.Second
	// dnsMaxTTL bounds how long a stale name may describe an address that has
	// since been reassigned.
	dnsMaxTTL = 30 * time.Minute
)

var errMalformedDNS = errors.New("malformed DNS message")

type dnsRecord struct {
	Address netip.Addr
	// Names are every label this address answered under, the queried name
	// first. A CNAME chain answers under the alias, so recording only the
	// record owner would lose the name the application - and the user's rule -
	// actually used.
	Names []string
	TTL   time.Duration
}

// parseDNSAnswers extracts the A and AAAA records of a response. A message
// that is not a response, or that cannot be parsed, yields no records: name
// learning is an optimisation and must never fail a lookup.
func parseDNSAnswers(message []byte) []dnsRecord {
	if len(message) < 12 || len(message) > dnsMaxMessageBytes {
		return nil
	}
	if message[2]&0x80 == 0 {
		return nil // not a response
	}
	if message[3]&0x0f != 0 {
		return nil // non-zero RCODE
	}

	questions := binary.BigEndian.Uint16(message[4:6])
	answers := binary.BigEndian.Uint16(message[6:8])
	if answers == 0 {
		return nil
	}

	offset := 12
	queried := ""
	for index := 0; index < int(questions); index++ {
		next, name, err := skipName(message, offset)
		if err != nil || next+4 > len(message) {
			return nil
		}
		if index == 0 {
			queried = name
		}
		offset = next + 4
	}

	var records []dnsRecord
	for index := 0; index < int(answers); index++ {
		next, name, err := skipName(message, offset)
		if err != nil || next+10 > len(message) {
			return records
		}
		recordType := binary.BigEndian.Uint16(message[next : next+2])
		ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
		length := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		data := next + 10
		if data+length > len(message) {
			return records
		}
		var address netip.Addr
		switch {
		case recordType == 1 && length == 4:
			address = netip.AddrFrom4([4]byte(message[data : data+4]))
		case recordType == 28 && length == 16:
			address = netip.AddrFrom16([16]byte(message[data : data+16]))
		}
		if address.IsValid() {
			// The queried name comes first because that is what a routing rule
			// is written against; the record's own owner follows so a rule
			// naming the CDN host matches too.
			records = append(records, dnsRecord{
				Address: address,
				Names:   distinctNames(queried, name),
				TTL:     boundedTTL(ttl),
			})
		}
		offset = data + length
	}
	return records
}

func distinctNames(first string, second string) []string {
	names := make([]string, 0, 2)
	if first != "" {
		names = append(names, first)
	}
	if second != "" && second != first {
		names = append(names, second)
	}
	return names
}

func boundedTTL(seconds uint32) time.Duration {
	ttl := time.Duration(seconds) * time.Second
	if ttl < dnsMinTTL {
		return dnsMinTTL
	}
	if ttl > dnsMaxTTL {
		return dnsMaxTTL
	}
	return ttl
}

// skipName walks a possibly compressed name and returns the offset just past
// it in the current record, together with the decoded name. A pointer moves
// reading backwards only, and the label budget bounds the walk, so a crafted
// message cannot loop here.
func skipName(message []byte, offset int) (int, string, error) {
	var builder strings.Builder
	next := -1
	jumps := 0
	for labels := 0; labels < dnsMaxNameLabels; labels++ {
		if offset < 0 || offset >= len(message) {
			return 0, "", errMalformedDNS
		}
		length := int(message[offset])
		switch {
		case length == 0:
			if next < 0 {
				next = offset + 1
			}
			return next, builder.String(), nil
		case length&0xc0 == 0xc0:
			if offset+1 >= len(message) {
				return 0, "", errMalformedDNS
			}
			target := int(binary.BigEndian.Uint16(message[offset:offset+2]) & 0x3fff)
			// A pointer must move strictly backwards; anything else is either a
			// loop or a forward reference this parser does not accept.
			if target >= offset {
				return 0, "", errMalformedDNS
			}
			if next < 0 {
				next = offset + 2
			}
			jumps++
			if jumps > dnsMaxNameLabels {
				return 0, "", errMalformedDNS
			}
			offset = target
		case length > 63:
			return 0, "", errMalformedDNS
		default:
			if offset+1+length > len(message) {
				return 0, "", errMalformedDNS
			}
			if builder.Len() > 0 {
				builder.WriteByte('.')
			}
			for _, character := range message[offset+1 : offset+1+length] {
				builder.WriteByte(lowerASCII(character))
			}
			offset += 1 + length
		}
	}
	return 0, "", errMalformedDNS
}

func lowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

// DomainCache remembers which name produced which address, so a flow to a
// literal address can still be matched against domain rules and the curated
// lists.
//
// The map is bounded and expiring rather than unbounded: a long session on a
// busy machine would otherwise accumulate every address the host ever
// resolved, and a name that has since been repointed would keep describing an
// address that now belongs to someone else.
type DomainCache struct {
	mu      sync.RWMutex
	entries map[netip.Addr]domainCacheEntry
	maximum int
	now     func() time.Time
}

type domainCacheEntry struct {
	names     []string
	expiresAt time.Time
}

// DefaultDomainCacheSize bounds the number of remembered addresses.
const DefaultDomainCacheSize = 8192

// NewDomainCache returns an empty cache. A maximum of zero selects
// DefaultDomainCacheSize.
func NewDomainCache(maximum int) *DomainCache {
	if maximum <= 0 {
		maximum = DefaultDomainCacheSize
	}
	return &DomainCache{
		entries: make(map[netip.Addr]domainCacheEntry),
		maximum: maximum,
		now:     time.Now,
	}
}

// Record remembers every address in a DNS response.
func (c *DomainCache) Record(records []dnsRecord) {
	if len(records) == 0 {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, record := range records {
		if len(record.Names) == 0 || !record.Address.IsValid() {
			continue
		}
		c.entries[record.Address.Unmap()] = domainCacheEntry{names: record.Names, expiresAt: now.Add(record.TTL)}
	}
	c.evictLocked(now)
}

// Lookup returns the names an address was last resolved from, queried name
// first, or nil.
func (c *DomainCache) Lookup(address netip.Addr) []string {
	c.mu.RLock()
	entry, ok := c.entries[address.Unmap()]
	c.mu.RUnlock()
	if !ok || c.now().After(entry.expiresAt) {
		return nil
	}
	return entry.names
}

// evictLocked drops expired entries, and then, if the cache is still over its
// bound, drops whatever the map iteration reaches first. Exact LRU would need
// a second index on the hot path of every DNS answer for no routing benefit:
// an evicted name only costs one flow its domain match, and the next lookup
// re-learns it.
func (c *DomainCache) evictLocked(now time.Time) {
	if len(c.entries) <= c.maximum {
		return
	}
	for address, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, address)
		}
	}
	for address := range c.entries {
		if len(c.entries) <= c.maximum {
			return
		}
		delete(c.entries, address)
	}
}
