package dataplane

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
)

// A domain rule is written against a name, and the DNS learning in dns.go is
// how a flow that only carries an address gets one. That learning has a gap
// the user meets exactly when they look: a browser that resolved the name
// before the tunnel came up, or resolves over DoH, never sends a query the
// adapter can see, so its connections arrive with no name and a domain rule
// quietly does not match. Process rules are unaffected, which makes the gap
// read as "domain routing is broken in browsers while applications work".
//
// The name is nevertheless in the first bytes the client sends: the SNI of a
// TLS ClientHello, or the Host header of a plain HTTP request. Reading it there
// closes the gap for every client, whatever it did about DNS. Nothing is
// modified or delayed beyond the read itself; the bytes are forwarded intact.

const (
	// sniffMaxBytes bounds how much of a flow is held back while looking for
	// its name. A ClientHello with post-quantum key shares is under 2 KiB; a
	// TLS record cannot exceed 16 KiB.
	sniffMaxBytes = 16 * 1024
	// tlsMaxHandshakeRecords bounds how many records a ClientHello may be
	// spread over before the sniffer stops reassembling. Real clients use one,
	// occasionally two; a stream of tiny records is not a hello worth waiting
	// for, and re-parsing it on every read would cost more than the wait.
	tlsMaxHandshakeRecords = 8
	// tlsRecordHeaderBytes is type, version and length.
	tlsRecordHeaderBytes    = 5
	tlsRecordHandshake      = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtensionServerName  = 0
	tlsServerNameHostName   = 0
)

// sniffClientName reads a name out of the opening bytes of a TCP flow.
//
// It returns the name when one is present, or an empty name together with
// needMore when the bytes so far are a prefix of something that may still
// carry one - the caller then reads on and calls again with the longer buffer.
// Anything that is neither a TLS ClientHello nor an HTTP request yields an
// empty name and needMore=false at once, so a flow that speaks another
// protocol is not held back for a name it will never send.
func sniffClientName(data []byte) (name string, needMore bool) {
	if len(data) == 0 {
		return "", true
	}
	if data[0] == tlsRecordHandshake {
		return sniffTLSServerName(data)
	}
	if looksLikeHTTPRequest(data) {
		return sniffHTTPHost(data)
	}
	return "", false
}

// sniffTLSServerName extracts the server_name extension of a ClientHello that
// may span several handshake records and arrive in several segments.
func sniffTLSServerName(data []byte) (string, bool) {
	// Collect the handshake fragments of the leading records. A ClientHello is
	// almost always one record, but a fragmented one is legal and does occur.
	var handshake []byte
	offset := 0
	for records := 0; ; records++ {
		if records >= tlsMaxHandshakeRecords {
			return "", false
		}
		if offset+tlsRecordHeaderBytes > len(data) {
			// A partial record header: only more bytes can tell.
			return "", len(data) < sniffMaxBytes
		}
		if data[offset] != tlsRecordHandshake || data[offset+1] != 0x03 {
			// Not a handshake record where one was expected.
			return "", false
		}
		length := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if length == 0 || length > sniffMaxBytes {
			return "", false
		}
		end := offset + tlsRecordHeaderBytes + length
		if end > len(data) {
			// The record is still arriving. Parse what is there: a ClientHello
			// that fits in the first record can be answered before the rest
			// of that record lands, which is the common case for a large hello.
			handshake = append(handshake, data[offset+tlsRecordHeaderBytes:]...)
			name, needMore := parseClientHelloServerName(handshake)
			if name != "" {
				return name, false
			}
			return "", needMore && len(data) < sniffMaxBytes
		}
		handshake = append(handshake, data[offset+tlsRecordHeaderBytes:end]...)
		name, needMore := parseClientHelloServerName(handshake)
		if name != "" {
			return name, false
		}
		if !needMore {
			return "", false
		}
		offset = end
		if offset >= len(data) {
			return "", len(data) < sniffMaxBytes
		}
	}
}

// parseClientHelloServerName walks a ClientHello handshake message. needMore
// is true when the message is a prefix that has not yet reached the
// extensions, or the extensions are cut off before server_name was seen.
func parseClientHelloServerName(handshake []byte) (string, bool) {
	if len(handshake) < 4 {
		return "", true
	}
	if handshake[0] != tlsHandshakeClientHello {
		return "", false
	}
	bodyLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if bodyLength > sniffMaxBytes {
		return "", false
	}
	body := handshake[4:]
	complete := len(body) >= bodyLength
	if complete {
		body = body[:bodyLength]
	}
	needMore := func() (string, bool) {
		return "", !complete
	}

	// client_version(2) random(32) session_id<0..32> cipher_suites<2..2^16-2>
	// compression_methods<1..2^8-1> extensions<0..2^16-1>
	position := 2 + 32
	if len(body) < position+1 {
		return needMore()
	}
	position += 1 + int(body[position])
	if len(body) < position+2 {
		return needMore()
	}
	position += 2 + int(binary.BigEndian.Uint16(body[position:position+2]))
	if len(body) < position+1 {
		return needMore()
	}
	position += 1 + int(body[position])
	if len(body) < position+2 {
		if complete {
			// A ClientHello without extensions carries no name.
			return "", false
		}
		return needMore()
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	extensionsEnd := position + extensionsLength
	for position+4 <= len(body) && position+4 <= extensionsEnd {
		extensionType := binary.BigEndian.Uint16(body[position : position+2])
		extensionLength := int(binary.BigEndian.Uint16(body[position+2 : position+4]))
		position += 4
		if position+extensionLength > len(body) {
			if extensionType == tlsExtensionServerName {
				return needMore()
			}
			// Another extension is cut off; server_name may follow it.
			return needMore()
		}
		if extensionType == tlsExtensionServerName {
			return serverNameFromExtension(body[position : position+extensionLength]), false
		}
		position += extensionLength
	}
	if position < extensionsEnd && !complete {
		return "", true
	}
	return "", false
}

// serverNameFromExtension reads the first host_name entry of a server_name
// extension. Anything malformed yields an empty name: a bad hello is the
// server's problem, not a reason to hold the flow.
func serverNameFromExtension(extension []byte) string {
	if len(extension) < 2 {
		return ""
	}
	listLength := int(binary.BigEndian.Uint16(extension[0:2]))
	list := extension[2:]
	if listLength > len(list) {
		listLength = len(list)
	}
	list = list[:listLength]
	for len(list) >= 3 {
		nameType := list[0]
		nameLength := int(binary.BigEndian.Uint16(list[1:3]))
		if 3+nameLength > len(list) {
			return ""
		}
		if nameType == tlsServerNameHostName {
			return normalizeSniffedName(string(list[3 : 3+nameLength]))
		}
		list = list[3+nameLength:]
	}
	return ""
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "), []byte("PROPFIND "),
}

// looksLikeHTTPRequest reports whether data starts like an HTTP/1.x request
// line, or is a prefix of one of the accepted methods.
func looksLikeHTTPRequest(data []byte) bool {
	for _, method := range httpMethods {
		if bytes.HasPrefix(data, method) {
			return true
		}
		if len(data) < len(method) && bytes.HasPrefix(method, data) {
			return true
		}
	}
	return false
}

// sniffHTTPHost returns the Host header of a plain HTTP/1.x request. The
// request line has to end and the headers have to reach Host: for an answer;
// until then, and until the header block ends without one, more bytes are
// asked for.
func sniffHTTPHost(data []byte) (string, bool) {
	if len(data) >= sniffMaxBytes {
		return "", false
	}
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		// Still inside the request line.
		return "", !bytes.ContainsAny(data, "\x00")
	}
	requestLine := data[:lineEnd]
	if !bytes.Contains(requestLine, []byte(" HTTP/1.")) {
		return "", false
	}
	headers := data[lineEnd+2:]
	terminated := bytes.Contains(headers, []byte("\r\n\r\n")) || bytes.HasPrefix(headers, []byte("\r\n"))
	for len(headers) > 0 {
		end := bytes.Index(headers, []byte("\r\n"))
		if end < 0 {
			break
		}
		line := headers[:end]
		if len(line) == 0 {
			break
		}
		if colon := bytes.IndexByte(line, ':'); colon > 0 && bytes.EqualFold(bytes.TrimSpace(line[:colon]), []byte("host")) {
			value := strings.TrimSpace(string(line[colon+1:]))
			return normalizeSniffedName(stripHostPort(value)), false
		}
		headers = headers[end+2:]
	}
	if terminated {
		// The header block ended without a Host; an absolute-form request
		// line is the only other place the name can be.
		return hostFromRequestTarget(requestLine), false
	}
	return "", true
}

// hostFromRequestTarget reads the authority of an absolute-form request line
// such as `GET http://example.org/ HTTP/1.1`, which proxies see and origin
// servers normally do not.
func hostFromRequestTarget(requestLine []byte) string {
	parts := bytes.SplitN(requestLine, []byte(" "), 3)
	if len(parts) < 2 {
		return ""
	}
	target := string(parts[1])
	lower := strings.ToLower(target)
	for _, scheme := range []string{"http://", "https://"} {
		if strings.HasPrefix(lower, scheme) {
			authority := target[len(scheme):]
			if slash := strings.IndexByte(authority, '/'); slash >= 0 {
				authority = authority[:slash]
			}
			if at := strings.LastIndexByte(authority, '@'); at >= 0 {
				authority = authority[at+1:]
			}
			return normalizeSniffedName(stripHostPort(authority))
		}
	}
	return ""
}

// stripHostPort removes a trailing :port from a host, leaving IPv6 literals
// intact.
func stripHostPort(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end >= 0 {
			return value[:end+1]
		}
		return value
	}
	if colon := strings.LastIndexByte(value, ':'); colon >= 0 && strings.Count(value, ":") == 1 {
		return value[:colon]
	}
	return value
}

// normalizeSniffedName lower-cases a name and rejects anything that is not a
// host name: an address literal adds nothing the flow did not already carry,
// and a value with characters outside the DNS alphabet is not a name a rule
// could have been written against.
func normalizeSniffedName(value string) string {
	name := strings.ToLower(strings.TrimSpace(value))
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return ""
	}
	if strings.HasPrefix(name, "[") || strings.Contains(name, ":") {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	if !strings.Contains(name, ".") {
		// A single label (a LAN host, or "localhost") is never selected by a
		// domain rule, which needs at least two labels; keep those flows
		// unattributed rather than recording a name they would not match on.
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			// An empty label (a leading, doubled or second trailing dot) is not
			// a name any resolver would have answered for.
			return ""
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
				continue
			}
			return ""
		}
	}
	return name
}
