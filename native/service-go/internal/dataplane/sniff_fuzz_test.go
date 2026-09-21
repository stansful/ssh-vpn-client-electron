package dataplane

import (
	"crypto/tls"
	"net"
	"testing"
)

func FuzzSniffClientName(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"))
	f.Add(buildClientHello("seed.example.org", 300))
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		name, needMore := sniffClientName(data)
		if name != "" && needMore {
			t.Fatalf("a name together with needMore")
		}
		if name != "" && normalizeSniffedName(name) != name {
			t.Fatalf("unnormalised name %q", name)
		}
	})
}

func FuzzQUICInitial(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x44, 0x00})
	hello := []byte{0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00}
	f.Add(cryptoFrame(0, hello))
	f.Fuzz(func(t *testing.T, data []byte) {
		sink := newCryptoReassembler()
		name, isQUIC, needMore := sniffQUICServerName(sink, data)
		if name != "" && (!isQUIC || needMore) {
			t.Fatalf("a name without isQUIC or with needMore")
		}
		// Frame parsing on arbitrary plaintext must not panic either.
		collectCryptoFrames(data, sink)
		_ = sink.contiguous()
	})
}

func FuzzParseClientHelloServerName(f *testing.F) {
	f.Add([]byte{})
	f.Add(tlsHandshakeMessageOrNil(clientHelloForFuzz("fuzz.example.org")))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseClientHelloServerName(data)
	})
}

func clientHelloForFuzz(name string) []byte {
	// crypto/tls needs a *testing.T-free path for the seed corpus.
	record := make(chan []byte, 1)
	go func() {
		defer close(record)
		client, server := net.Pipe()
		defer server.Close()
		go func() {
			_ = tls.Client(client, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
			_ = client.Close()
		}()
		buffer := make([]byte, 64*1024)
		read, err := server.Read(buffer)
		if err == nil {
			record <- buffer[:read]
		}
	}()
	return <-record
}

func tlsHandshakeMessageOrNil(record []byte) []byte {
	if len(record) < 5 {
		return nil
	}
	length := int(record[3])<<8 | int(record[4])
	if 5+length > len(record) {
		return nil
	}
	return record[5 : 5+length]
}
