package dataplane

import (
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// The vectors of RFC 9001 Appendix A.1.
func TestQUICInitialKeyDerivation(t *testing.T) {
	connectionID := mustHex(t, "8394c8f03e515708")
	keys, err := deriveQUICInitialKeys(quicVersion1, connectionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(keys.iv); got != "fa044b2f42a3fd3b46fb255c" {
		t.Fatalf("iv = %s", got)
	}
	// The header-protection key is only reachable through the cipher: check
	// it by encrypting a zero block with the expected key and comparing.
	expectedHP, err := aes.NewCipher(mustHex(t, "9f50449e04a0e810283a1e9933adedd2"))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 16)
	got := make([]byte, 16)
	expectedHP.Encrypt(want, make([]byte, 16))
	keys.hp.Encrypt(got, make([]byte, 16))
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("header protection key differs from the RFC 9001 vector")
	}
	// And the payload key, through its own derivation step.
	initialSecret := mustHex(t, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", 32)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(clientSecret); got != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Fatalf("client initial secret = %s", got)
	}
	key, err := hkdfExpandLabel(clientSecret, "quic key", 16)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != "1f369613dd76d5467730efcbe3b1a22d" {
		t.Fatalf("key = %s", got)
	}
}

// sealInitial builds a client Initial packet the way a client would: the
// inverse of readInitialPacket, used to exercise it with real ClientHellos.
func sealInitial(t *testing.T, version uint32, connectionID []byte, packetNumber uint32, frames []byte, padTo int) []byte {
	t.Helper()
	keys, err := deriveQUICInitialKeys(version, connectionID)
	if err != nil {
		t.Fatal(err)
	}
	const packetNumberLength = 4
	first := byte(0xc0 | (packetNumberLength - 1))
	if version == quicVersion2 {
		first |= 0x10 // Initial is type 1 in v2
	}
	header := []byte{first}
	header = binary.BigEndian.AppendUint32(header, version)
	header = append(header, byte(len(connectionID)))
	header = append(header, connectionID...)
	header = append(header, 0) // empty source connection id
	header = append(header, 0) // token length
	payload := frames
	if padTo > len(payload)+packetNumberLength+16 {
		payload = append(append([]byte(nil), frames...), make([]byte, padTo-len(frames)-packetNumberLength-16)...)
	}
	length := packetNumberLength + len(payload) + 16
	header = append(header, 0x40|byte(length>>8), byte(length)) // 2-byte varint
	packetNumberOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, packetNumber)
	nonce := append([]byte(nil), keys.iv...)
	for index := 0; index < 4; index++ {
		nonce[len(nonce)-1-index] ^= byte(packetNumber >> (8 * index))
	}
	packet := keys.aead.Seal(append([]byte(nil), header...), nonce, payload, header)
	sample := packet[packetNumberOffset+4 : packetNumberOffset+4+quicSampleBytes]
	mask := make([]byte, aes.BlockSize)
	keys.hp.Encrypt(mask, sample)
	packet[0] ^= mask[0] & 0x0f
	for index := 0; index < packetNumberLength; index++ {
		packet[packetNumberOffset+index] ^= mask[1+index]
	}
	return packet
}

func cryptoFrame(offset int, data []byte) []byte {
	frame := []byte{0x06}
	frame = appendVarint(frame, uint64(offset))
	frame = appendVarint(frame, uint64(len(data)))
	return append(frame, data...)
}

func appendVarint(buffer []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(buffer, byte(value))
	case value < 1<<14:
		return append(buffer, 0x40|byte(value>>8), byte(value))
	default:
		return append(buffer, 0x80|byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
}

// tlsHandshakeMessage strips the record layer from a captured ClientHello.
func tlsHandshakeMessage(t *testing.T, record []byte) []byte {
	t.Helper()
	length := int(binary.BigEndian.Uint16(record[3:5]))
	return record[5 : 5+length]
}

func TestSniffQUICServerNameFromOneDatagram(t *testing.T) {
	for _, version := range []uint32{quicVersion1, quicVersion2} {
		hello := tlsHandshakeMessage(t, clientHelloFor(t, "quic.example.org", tls.VersionTLS13))
		frames := append([]byte{0x01}, cryptoFrame(0, hello)...) // a PING first, as some clients do
		datagram := sealInitial(t, version, mustHex(t, "8394c8f03e515708"), 0, frames, 1200)
		original := append([]byte(nil), datagram...)
		sink := newCryptoReassembler()
		name, isQUIC, needMore := sniffQUICServerName(sink, datagram)
		if !isQUIC || needMore || name != "quic.example.org" {
			t.Fatalf("version %x: name=%q isQUIC=%v needMore=%v", version, name, isQUIC, needMore)
		}
		if hex.EncodeToString(datagram) != hex.EncodeToString(original) {
			t.Fatalf("version %x: the datagram was modified", version)
		}
	}
}

func TestSniffQUICServerNameAcrossDatagrams(t *testing.T) {
	hello := tlsHandshakeMessage(t, clientHelloFor(t, "split.example.org", tls.VersionTLS13))
	cut := len(hello) - 40
	// The second half arrives first, then an ACK-bearing packet with the first half.
	second := sealInitial(t, quicVersion1, mustHex(t, "0102030405060708"), 1, cryptoFrame(cut, hello[cut:]), 1200)
	ack := []byte{0x02, 0x00, 0x00, 0x00, 0x00} // ACK of packet 0, no ranges
	first := sealInitial(t, quicVersion1, mustHex(t, "0102030405060708"), 2, append(ack, cryptoFrame(0, hello[:cut])...), 1200)
	sink := newCryptoReassembler()
	name, isQUIC, needMore := sniffQUICServerName(sink, second)
	if !isQUIC || name != "" || !needMore {
		t.Fatalf("after the tail alone: name=%q isQUIC=%v needMore=%v", name, isQUIC, needMore)
	}
	name, isQUIC, needMore = sniffQUICServerName(sink, first)
	if !isQUIC || needMore || name != "split.example.org" {
		t.Fatalf("after both: name=%q isQUIC=%v needMore=%v", name, isQUIC, needMore)
	}
}

func TestSniffQUICCoalescedAndForeignPackets(t *testing.T) {
	hello := tlsHandshakeMessage(t, clientHelloFor(t, "coalesced.example.org", tls.VersionTLS13))
	initial := sealInitial(t, quicVersion1, mustHex(t, "a1a2a3a4"), 0, cryptoFrame(0, hello), 0)
	// A 0-RTT packet coalesced behind it, opaque to us, must be skipped by its length.
	zeroRTT := []byte{0xd0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xa1, 0xa2, 0xa3, 0xa4, 0x00}
	zeroRTT = append(zeroRTT, 0x40|0x00, 0x30) // length 48
	zeroRTT = append(zeroRTT, make([]byte, 48)...)
	datagram := append(append([]byte(nil), initial...), zeroRTT...)
	sink := newCryptoReassembler()
	if name, isQUIC, _ := sniffQUICServerName(sink, datagram); !isQUIC || name != "coalesced.example.org" {
		t.Fatalf("coalesced: name=%q isQUIC=%v", name, isQUIC)
	}
	// Not QUIC at all: a verdict at once.
	for _, datagram := range [][]byte{[]byte("hello"), {0x00, 0x01}, {0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}} {
		if name, isQUIC, needMore := sniffQUICServerName(newCryptoReassembler(), datagram); isQUIC || needMore || name != "" {
			t.Fatalf("%x: name=%q isQUIC=%v needMore=%v", datagram, name, isQUIC, needMore)
		}
	}
	// A QUIC packet that does not decrypt with client Initial keys (a server's
	// packet, or damage) is QUIC without a name, and does not poison the sink.
	damaged := append([]byte(nil), initial...)
	damaged[len(damaged)-1] ^= 0xff
	if name, isQUIC, needMore := sniffQUICServerName(newCryptoReassembler(), damaged); !isQUIC || name != "" || !needMore {
		t.Fatalf("damaged: name=%q isQUIC=%v needMore=%v", name, isQUIC, needMore)
	}
}

func TestReadVarint(t *testing.T) {
	cases := []struct {
		data  []byte
		value uint64
		size  int
	}{
		{[]byte{0x25}, 37, 1},
		{[]byte{0x7b, 0xbd}, 15293, 2},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8},
		{[]byte{0x40}, 0, 0},
	}
	for _, c := range cases {
		value, size := readVarint(c.data)
		if value != c.value || size != c.size {
			t.Fatalf("%x: got %d/%d want %d/%d", c.data, value, size, c.value, c.size)
		}
	}
}

// RFC 9001 Appendix A.2: the protected client Initial packet. Its ClientHello
// names example.com; decrypting it end to end proves the key schedule, the
// header protection and the AEAD framing against the specification's own
// vector rather than against this file's mirror image of itself.
const rfc9001ClientInitial = `
c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934`

func TestSniffQUICDecryptsTheRFC9001ClientInitial(t *testing.T) {
	packet := mustHex(t, strings.Join(strings.Fields(rfc9001ClientInitial), ""))
	if len(packet) != 1200 {
		t.Fatalf("vector is %d bytes", len(packet))
	}
	original := append([]byte(nil), packet...)
	sink := newCryptoReassembler()
	name, isQUIC, needMore := sniffQUICServerName(sink, packet)
	if !isQUIC || needMore || name != "example.com" {
		t.Fatalf("name=%q isQUIC=%v needMore=%v", name, isQUIC, needMore)
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("the datagram was modified")
	}
}
