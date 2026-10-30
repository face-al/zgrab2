package sslv2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/zmap/zgrab2"
)

// fixture is a SERVER-HELLO record captured from OpenSSL 1.0.2u
// (s_server -ssl2) in reply to the scanner's CLIENT-HELLO: 2-byte header,
// a self-signed certificate, four cipher specs and a 16-byte connection id.
func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/openssl-1.0.2u-server-hello.bin")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const fixtureConnectionID = "e99ed85ee1967925dafac5bd6b22fca2"

// record wraps body in a record with a 2-byte header.
func record(body []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, 0x8000|uint16(len(body))), body...)
}

// record3 wraps body in a record with a 3-byte header and the given padding byte.
func record3(body []byte, padding byte) []byte {
	return append([]byte{byte(len(body) >> 8), byte(len(body)), padding}, body...)
}

// serverHello encodes a SERVER-HELLO message with the given fields.
func serverHello(hit, certType byte, ver uint16, cert, specs, connID []byte) []byte {
	b := []byte{msgServerHello, hit, certType}
	b = binary.BigEndian.AppendUint16(b, ver)
	b = binary.BigEndian.AppendUint16(b, uint16(len(cert)))
	b = binary.BigEndian.AppendUint16(b, uint16(len(specs)))
	b = binary.BigEndian.AppendUint16(b, uint16(len(connID)))
	b = append(b, cert...)
	b = append(b, specs...)
	return append(b, connID...)
}

// errorMessage encodes an ERROR message with the given code.
func errorMessage(code uint16) []byte {
	return binary.BigEndian.AppendUint16([]byte{msgError}, code)
}

var (
	testSpecs  = []byte{0x01, 0x00, 0x80, 0x07, 0x00, 0xc0}
	testConnID = bytes.Repeat([]byte{0xab}, 16)
	notACert   = []byte("not a certificate")
)

// writePieces writes b to conn in the given number of pieces.
func writePieces(conn net.Conn, b []byte, pieces int) {
	size := max((len(b)+pieces-1)/pieces, 1)
	for len(b) > 0 {
		n := min(size, len(b))
		conn.Write(b[:n])
		b = b[n:]
	}
}

// runServer runs a fake server on serverConn: it reads and checks the
// CLIENT-HELLO, writes reply in the given number of pieces and closes the
// connection. The returned channel receives the server's error, nil if none.
func runServer(serverConn net.Conn, reply []byte, pieces int) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		buf := make([]byte, len(clientHello(make([]byte, challengeLength))))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			done <- fmt.Errorf("could not read CLIENT-HELLO: %w", err)
			return
		}
		if !bytes.Equal(buf, clientHello(buf[len(buf)-challengeLength:])) {
			done <- fmt.Errorf("unexpected CLIENT-HELLO %x", buf)
			return
		}
		writePieces(serverConn, reply, pieces)
		done <- nil
	}()
	return done
}

func scan(t *testing.T, reply []byte, pieces int) (zgrab2.ScanStatus, *Result, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	srvDone := runServer(serverConn, reply, pieces)
	status, result, err := Probe(clientConn)
	clientConn.Close()
	if srvErr := <-srvDone; srvErr != nil {
		t.Errorf("server: %v", srvErr)
	}
	return status, result, err
}

// TestClientHelloBytes checks the CLIENT-HELLO against the bytes of
// TLS-Attacker's SSL2 ClientHello.
func TestClientHelloBytes(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x5a}, challengeLength)
	expected := "802e" + "01" + "0002" + "0015" + "0000" + "0010" +
		"010080" + "020080" + "030080" + "040080" + "050080" + "060040" + "0700c0" +
		strings.Repeat("5a", challengeLength)
	if got := hex.EncodeToString(clientHello(challenge)); got != expected {
		t.Errorf("clientHello() = %s, wanted %s", got, expected)
	}
}

func TestOpenSSLServerHello(t *testing.T) {
	for _, pieces := range []int{1, 7, 805} {
		status, result, err := scan(t, fixture(t), pieces)
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("%d pieces: expected SCAN_SUCCESS, got %s (%v)", pieces, status, err)
		}
		hello := result.ServerHello
		if hello == nil {
			t.Fatal("expected SERVER-HELLO")
		}
		if result.HeaderLength != 2 || result.Raw != hex.EncodeToString(fixture(t)) {
			t.Errorf("unexpected header length %d or raw %s", result.HeaderLength, result.Raw)
		}
		if hello.SessionIDHit != 0 || hello.CertificateType != 1 || hello.Version != 2 {
			t.Errorf("unexpected SERVER-HELLO fields %+v", hello)
		}
		wantSpecs := []string{"SSL_CK_RC4_128_WITH_MD5", "SSL_CK_RC2_128_CBC_WITH_MD5", "SSL_CK_IDEA_128_CBC_WITH_MD5", "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"}
		if strings.Join(hello.CipherSpecs, ",") != strings.Join(wantSpecs, ",") || hello.CipherSpecsRaw != "010080030080050080"+"0700c0" {
			t.Errorf("unexpected cipher specs %v (%s)", hello.CipherSpecs, hello.CipherSpecsRaw)
		}
		if hello.ConnectionID != fixtureConnectionID {
			t.Errorf("unexpected connection id %s", hello.ConnectionID)
		}
		if hello.Certificate == nil || len(hello.Certificate.Raw) != 0x2fc || hello.Certificate.Parsed == nil || hello.Certificate.ParseError != "" {
			t.Fatalf("expected parsed certificate, got %+v", hello.Certificate)
		}
		if result.Error != nil {
			t.Errorf("expected no ERROR, got %+v", result.Error)
		}
	}
}

func TestServerHelloThreeByteHeader(t *testing.T) {
	status, result, err := scan(t, record3(fixture(t)[2:], 0), 3)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if result.HeaderLength != 3 || result.ServerHello.ConnectionID != fixtureConnectionID {
		t.Errorf("unexpected result %+v", result)
	}
}

// TestServerHelloNoCipherSpecs checks that a SERVER-HELLO with a certificate
// and an empty cipher spec list still succeeds (the server committed to
// SSLv2; only the CLIENT-HELLO list must be non-empty, draft 5.5.1).
func TestServerHelloNoCipherSpecs(t *testing.T) {
	cert := fixture(t)[13 : 13+0x2fc]
	status, result, err := scan(t, record(serverHello(0, 1, 2, cert, nil, testConnID)), 1)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if len(result.ServerHello.CipherSpecs) != 0 || result.ServerHello.CipherSpecsRaw != "" {
		t.Errorf("unexpected cipher specs %+v", result.ServerHello)
	}
}

// TestCertificateParseError checks that a certificate that does not parse
// does not fail the scan.
func TestCertificateParseError(t *testing.T) {
	status, result, err := scan(t, record(serverHello(0, 1, 2, notACert, append(testSpecs, 0x08, 0x00, 0x80), testConnID)), 1)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	cert := result.ServerHello.Certificate
	if cert == nil || !bytes.Equal(cert.Raw, notACert) || cert.Parsed != nil || cert.ParseError == "" {
		t.Errorf("expected unparsed certificate with parse error, got %+v", cert)
	}
	if got := strings.Join(result.ServerHello.CipherSpecs, ","); got != "SSL_CK_RC4_128_WITH_MD5,SSL_CK_DES_192_EDE3_CBC_WITH_MD5,080080" {
		t.Errorf("unexpected cipher specs %s", got)
	}
}

func TestErrorMessage(t *testing.T) {
	for code, name := range errorNames {
		status, result, _ := scan(t, record(errorMessage(code)), 2)
		if status != zgrab2.SCAN_APPLICATION_ERROR {
			t.Fatalf("code %d: expected SCAN_APPLICATION_ERROR, got %s", code, status)
		}
		if result.Error == nil || result.Error.Code != code || result.Error.Name != name || result.ServerHello != nil {
			t.Errorf("code %d: unexpected result %+v", code, result)
		}
		if result.Raw != hex.EncodeToString(record(errorMessage(code))) {
			t.Errorf("code %d: unexpected raw %s", code, result.Raw)
		}
	}
}

func TestProtocolErrors(t *testing.T) {
	cert := []byte("certificate")
	tlsAlert := []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46}
	testTable := map[string][]byte{
		"tls alert":           tlsAlert,
		"tls handshake":       {0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		"truncated tls alert": tlsAlert[:4],
		"http":                []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"smtp":                []byte("220 mail.example.com ESMTP\r\n"),
		"one byte":            {0x80},
		"truncated header":    {0x00, 0x05},
		"truncated record":    fixture(t)[:400],
		"empty record":        {0x80, 0x00},
		"padding":             record3(fixture(t)[2:], 1),
		"security escape":     append([]byte{0x40}, record3(fixture(t)[2:], 0)[1:]...),
		"unknown error code":  record(errorMessage(3)),
		"long error":          record(append(errorMessage(1), 0)),
		"short server hello":  record(serverHello(0, 1, 2, nil, nil, nil)[:10]),
		"server verify":       record(append([]byte{5}, testConnID...)),
		"client hello":        clientHello(testConnID),
		"session id hit":      record(serverHello(1, 1, 2, cert, testSpecs, testConnID)),
		"session id hit only": record(serverHello(1, 0, 2, nil, nil, testConnID)),
		"certificate type":    record(serverHello(0, 2, 2, cert, testSpecs, testConnID)),
		"version 3.0":         record(serverHello(0, 1, 0x0300, cert, testSpecs, testConnID)),
		"no certificate":      record(serverHello(0, 1, 2, nil, testSpecs, testConnID)),
		"partial cipher spec": record(serverHello(0, 1, 2, cert, testSpecs[:4], testConnID)),
		"short connection id": record(serverHello(0, 1, 2, cert, testSpecs, testConnID[:15])),
		"long connection id":  record(serverHello(0, 1, 2, cert, testSpecs, bytes.Repeat(testConnID, 3)[:33])),
		"trailing bytes":      record(append(serverHello(0, 1, 2, cert, testSpecs, testConnID), 0)),
		"lengths too long":    record(serverHello(0, 1, 2, cert, testSpecs, testConnID)[:40]),
	}
	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			status, result, err := scan(t, reply, 2)
			if status != zgrab2.SCAN_PROTOCOL_ERROR {
				t.Fatalf("expected SCAN_PROTOCOL_ERROR, got %s (%v)", status, err)
			}
			if result == nil || result.ServerHello != nil || result.Error != nil {
				t.Fatalf("expected only raw bytes, got %+v", result)
			}
			if !strings.HasPrefix(hex.EncodeToString(reply), result.Raw) || result.Raw == "" {
				t.Errorf("raw %s is not a prefix of the reply %x", result.Raw, reply)
			}
		})
	}
}

// TestTLSAlertRaw checks that a TLS reply is kept whole.
func TestTLSAlertRaw(t *testing.T) {
	_, result, err := scan(t, []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46}, 1)
	if result == nil || result.Raw != "15030100020246" {
		t.Errorf("expected the TLS alert in raw, got %+v", result)
	}
	if err == nil || !strings.Contains(err.Error(), "TLS record") {
		t.Errorf("expected a TLS record error, got %v", err)
	}
}

func TestConnectionClosed(t *testing.T) {
	status, result, _ := scan(t, nil, 1)
	if status != zgrab2.SCAN_CONNECTION_CLOSED {
		t.Fatalf("expected SCAN_CONNECTION_CLOSED, got %s", status)
	}
	if result != nil {
		t.Errorf("expected no result, got %+v", result)
	}
}

// TestRawCap checks that raw is capped at maxRawLength bytes.
func TestRawCap(t *testing.T) {
	cert := bytes.Repeat([]byte{0x30}, 5000)
	status, result, err := scan(t, record(serverHello(0, 1, 2, cert, testSpecs, testConnID)), 4)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if len(result.Raw) != 2*maxRawLength {
		t.Errorf("expected %d hex characters of raw, got %d", 2*maxRawLength, len(result.Raw))
	}
	if len(result.ServerHello.Certificate.Raw) != len(cert) {
		t.Errorf("expected whole certificate, got %d bytes", len(result.ServerHello.Certificate.Raw))
	}
}
