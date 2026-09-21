package dataplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// A browser that already knows a site speaks HTTP/3 opens it over QUIC first,
// and only falls back to TCP when the QUIC attempt gets no answer. The SSH
// transport carries no datagrams, so a selected site's QUIC must be refused
// for that fallback to happen (see Verdict) - and it can only be refused if
// the flow is recognised as selected. With no name learned for the address
// yet, the first datagram would go out directly and the site would load
// outside the tunnel while its TCP twin was being routed into it.
//
// The name is in that first datagram: a QUIC Initial packet carries the TLS
// ClientHello, protected with keys that are derived from values in the packet
// itself (RFC 9001 section 5.2) precisely so that any on-path element can read
// it. This file reads it. Nothing is altered; the datagrams are forwarded as
// they arrived.

const (
	quicVersion1 = 0x00000001
	quicVersion2 = 0x6b3343cf
	// quicMaxInitialDatagrams bounds how many datagrams are inspected before
	// giving up on a hello that never completes.
	quicMaxInitialDatagrams = 4
	// quicMaxCryptoBytes bounds the reassembled ClientHello.
	quicMaxCryptoBytes = 16 * 1024
	quicSampleBytes    = 16
)

var (
	quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicV2Salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

	errNotQUIC = errors.New("not a QUIC long-header packet")
)

// quicInitialKeys are the client's Initial packet protection keys for one
// destination connection ID.
type quicInitialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// deriveQUICInitialKeys implements RFC 9001 section 5.2 for the client side.
func deriveQUICInitialKeys(version uint32, destinationConnectionID []byte) (*quicInitialKeys, error) {
	salt := quicV1Salt
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if version == quicVersion2 {
		salt = quicV2Salt
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initialSecret, err := hkdf.Extract(sha256.New, destinationConnectionID, salt)
	if err != nil {
		return nil, err
	}
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, err := hkdfExpandLabel(clientSecret, keyLabel, 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabel(clientSecret, ivLabel, 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := hkdfExpandLabel(clientSecret, hpLabel, 16)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	return &quicInitialKeys{aead: aead, iv: iv, hp: hp}, nil
}

// hkdfExpandLabel is the TLS 1.3 HKDF-Expand-Label with an empty context.
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0) // context length
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// cryptoReassembler collects CRYPTO frame data by stream offset and hands out
// the contiguous prefix from offset zero, which is where the ClientHello
// starts.
type cryptoReassembler struct {
	segments map[uint64][]byte
	total    int
}

func newCryptoReassembler() *cryptoReassembler {
	return &cryptoReassembler{segments: make(map[uint64][]byte)}
}

func (r *cryptoReassembler) add(offset uint64, data []byte) {
	if len(data) == 0 || offset > quicMaxCryptoBytes || r.total+len(data) > quicMaxCryptoBytes {
		return
	}
	if existing, ok := r.segments[offset]; ok && len(existing) >= len(data) {
		return
	}
	r.segments[offset] = append([]byte(nil), data...)
	r.total += len(data)
}

func (r *cryptoReassembler) contiguous() []byte {
	offsets := make([]uint64, 0, len(r.segments))
	for offset := range r.segments {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	var stream []byte
	for _, offset := range offsets {
		if offset > uint64(len(stream)) {
			break
		}
		segment := r.segments[offset]
		skip := uint64(len(stream)) - offset
		if skip >= uint64(len(segment)) {
			continue
		}
		stream = append(stream, segment[skip:]...)
	}
	return stream
}

// quicInitialCryptoFrames decrypts every Initial packet coalesced in one
// client datagram and feeds their CRYPTO frames to sink. It reports whether
// the datagram was a QUIC long-header datagram at all, so a caller can stop
// looking at flows that speak something else on the port.
func quicInitialCryptoFrames(datagram []byte, sink *cryptoReassembler) (isQUIC bool) {
	// Header protection removal writes into the packet, and the datagram is
	// forwarded afterwards exactly as it came, so work on a copy.
	packet := append([]byte(nil), datagram...)
	for len(packet) > 0 {
		consumed, err := readInitialPacket(packet, sink)
		if err != nil {
			return isQUIC
		}
		isQUIC = true
		if consumed <= 0 || consumed > len(packet) {
			return isQUIC
		}
		packet = packet[consumed:]
	}
	return isQUIC
}

// readInitialPacket parses one long-header packet at the start of packet,
// decrypts it if it is an Initial packet, and returns the bytes it occupied.
func readInitialPacket(packet []byte, sink *cryptoReassembler) (int, error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return 0, errNotQUIC
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != quicVersion1 && version != quicVersion2 {
		return 0, errNotQUIC
	}
	position := 5
	destinationLength := int(packet[position])
	position++
	if destinationLength > 20 || position+destinationLength+1 > len(packet) {
		return 0, errNotQUIC
	}
	destinationConnectionID := packet[position : position+destinationLength]
	position += destinationLength
	sourceLength := int(packet[position])
	position++
	if sourceLength > 20 || position+sourceLength > len(packet) {
		return 0, errNotQUIC
	}
	position += sourceLength

	packetType := (packet[0] & 0x30) >> 4
	initialType := byte(0)
	retryType := byte(3)
	if version == quicVersion2 {
		initialType = 1
		retryType = 0
	}
	if packetType == retryType {
		// A Retry packet has no length field; it is never sent by a client.
		return 0, errNotQUIC
	}
	if packetType == initialType {
		tokenLength, size := readVarint(packet[position:])
		if size == 0 || uint64(position+size)+tokenLength > uint64(len(packet)) {
			return 0, errNotQUIC
		}
		position += size + int(tokenLength)
	}
	length, size := readVarint(packet[position:])
	if size == 0 {
		return 0, errNotQUIC
	}
	position += size
	packetNumberOffset := position
	end := packetNumberOffset + int(length)
	if length > uint64(len(packet)) || end > len(packet) || length < 4+quicSampleBytes {
		return 0, errNotQUIC
	}
	if packetType != initialType {
		// A coalesced 0-RTT or Handshake packet carries no ClientHello.
		return end, nil
	}

	keys, err := deriveQUICInitialKeys(version, destinationConnectionID)
	if err != nil {
		return 0, err
	}
	sample := packet[packetNumberOffset+4 : packetNumberOffset+4+quicSampleBytes]
	mask := make([]byte, aes.BlockSize)
	keys.hp.Encrypt(mask, sample)
	packet[0] ^= mask[0] & 0x0f
	packetNumberLength := int(packet[0]&0x03) + 1
	var packetNumber uint64
	for index := 0; index < packetNumberLength; index++ {
		packet[packetNumberOffset+index] ^= mask[1+index]
		packetNumber = packetNumber<<8 | uint64(packet[packetNumberOffset+index])
	}
	header := packet[:packetNumberOffset+packetNumberLength]
	ciphertext := packet[packetNumberOffset+packetNumberLength : end]
	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	for index := 0; index < 8; index++ {
		nonce[len(nonce)-1-index] ^= byte(packetNumber >> (8 * index))
	}
	plaintext, err := keys.aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		// The keys did not fit: the packet is not a client Initial after all,
		// or it was damaged. Either way there is nothing to read here, and the
		// caller must not mistake the failure for "not QUIC".
		return end, nil
	}
	collectCryptoFrames(plaintext, sink)
	return end, nil
}

// collectCryptoFrames walks the frames of a decrypted Initial payload. Only
// the frame types a client may send in an Initial packet are understood; the
// walk stops at anything else.
func collectCryptoFrames(payload []byte, sink *cryptoReassembler) {
	position := 0
	for position < len(payload) {
		frameType, size := readVarint(payload[position:])
		if size == 0 {
			return
		}
		position += size
		switch frameType {
		case 0x00: // PADDING
			continue
		case 0x01: // PING
			continue
		case 0x02, 0x03: // ACK
			fields := 4
			if frameType == 0x03 {
				fields = 7
			}
			var rangeCount uint64
			for index := 0; index < fields; index++ {
				value, size := readVarint(payload[position:])
				if size == 0 {
					return
				}
				position += size
				if index == 2 {
					rangeCount = value
					// gap/length pairs follow the first range.
					fields += 2 * int(min(rangeCount, 1024))
				}
			}
		case 0x06: // CRYPTO
			offset, size := readVarint(payload[position:])
			if size == 0 {
				return
			}
			position += size
			length, size := readVarint(payload[position:])
			if size == 0 || uint64(position+size)+length > uint64(len(payload)) {
				return
			}
			position += size
			sink.add(offset, payload[position:position+int(length)])
			position += int(length)
		default:
			return
		}
	}
}

// readVarint decodes a QUIC variable-length integer, returning the value and
// the number of bytes it used, or 0 when the buffer is too short.
func readVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0
	}
	value := uint64(data[0] & 0x3f)
	for index := 1; index < size; index++ {
		value = value<<8 | uint64(data[index])
	}
	return value, size
}

// sniffQUICServerName reads the ClientHello server name out of the client's
// Initial datagrams. It returns needMore while the hello is still incomplete
// and the datagrams so far were QUIC, so the caller can wait for the next one.
func sniffQUICServerName(sink *cryptoReassembler, datagram []byte) (name string, isQUIC bool, needMore bool) {
	if !quicInitialCryptoFrames(datagram, sink) {
		return "", false, false
	}
	stream := sink.contiguous()
	if len(stream) == 0 {
		return "", true, true
	}
	name, needMore = parseClientHelloServerName(stream)
	return name, true, needMore
}
