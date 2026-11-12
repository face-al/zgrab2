package pop3

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"os"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

func TestPOP3SHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{POP3Secure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 995}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestPOP3STARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("+OK POP3 ready\r\n"))
		serverConn.Read(buf) // STLS
		serverConn.Write([]byte("+OK Begin TLS\r\n"))
	}()

	scanner := &Scanner{config: &Flags{StartTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 110}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestPOP3SHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(srv *stdtls.Conn) {
		srv.Write([]byte("+OK POP3 ready\r\n"))
	})

	scanner := &Scanner{config: &Flags{POP3Secure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 995}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Errorf("expected SCAN_SUCCESS, got %s", status)
	}
	pop3Result, ok := result.(*ScanResults)
	if !ok || pop3Result == nil {
		t.Fatal("expected non-nil *ScanResults")
	}
	if pop3Result.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !pop3Result.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

// fakeServer runs the plaintext dialog of a POP3 server up to and
// including reply to the upgrade command, then calls fn.
func fakeServer(serverConn net.Conn, reply string, fn func(net.Conn)) {
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("+OK POP3 ready\r\n"))
		serverConn.Read(buf) // STLS
		serverConn.Write([]byte(reply))
		fn(serverConn)
	}()
}

// scanSSLv2 runs an --sslv2 scan against a fake POP3 server that accepts
// the upgrade and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	fakeServer(serverConn, "+OK Begin TLS\r\n", fn)

	scanner := &Scanner{config: &Flags{StartTLS: true, SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 110}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	pop3Result, _ := result.(*ScanResults)
	return status, pop3Result
}

func TestSSLv2UpgradeRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	fakeServer(serverConn, "-ERR TLS not available\r\n", func(net.Conn) {})

	scanner := &Scanner{config: &Flags{StartTLS: true, SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 110}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	// the module maps a refused upgrade to SCAN_UNKNOWN_ERROR (error not typed)
	if status != zgrab2.SCAN_UNKNOWN_ERROR {
		t.Errorf("expected SCAN_UNKNOWN_ERROR, got %s", status)
	}
	if pop3Result, _ := result.(*ScanResults); pop3Result == nil || pop3Result.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
	}
}

func TestSSLv2Validate(t *testing.T) {
	if err := (Flags{POP3Secure: true, SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --pop3s with --sslv2")
	}
	if err := (Flags{SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --sslv2 without --starttls")
	}
	if err := (Flags{StartTLS: true, SSLv2: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// sslv2Server returns the server side of the SSL 2.0 probe: it reads the
// 48-byte CLIENT-HELLO, checks its header and version, and writes reply.
func sslv2Server(t *testing.T, reply []byte) func(net.Conn) {
	return func(conn net.Conn) {
		hello := make([]byte, 48)
		if _, err := io.ReadFull(conn, hello); err != nil {
			t.Errorf("reading CLIENT-HELLO: %v", err)

			return
		}
		if !bytes.HasPrefix(hello, []byte{0x80, 0x2e, 0x01}) {
			t.Errorf("unexpected CLIENT-HELLO prefix %x", hello[:3])
		}
		conn.Write(reply)
	}
}

func TestSSLv2Upgrade(t *testing.T) {
	serverHello, err := os.ReadFile("../../lib/sslv2/testdata/openssl-1.0.2u-server-hello.bin")
	if err != nil {
		t.Fatalf("reading SERVER-HELLO fixture: %v", err)
	}

	t.Run("server hello", func(t *testing.T) {
		status, result := scanSSLv2(t, sslv2Server(t, serverHello))
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("expected SCAN_SUCCESS, got %s", status)
		}
		if result == nil || result.SSLv2 == nil {
			t.Fatalf("expected sslv2 result, got %+v", result)
		}
		if result.SSLv2.Status != zgrab2.SCAN_SUCCESS {
			t.Errorf("expected sslv2 status SCAN_SUCCESS, got %s", result.SSLv2.Status)
		}
		if result.SSLv2.Result == nil || result.SSLv2.ServerHello == nil {
			t.Errorf("expected SERVER-HELLO, got %+v", result.SSLv2.Result)
		}
		if result.TLSLog != nil {
			t.Error("expected no TLS log")
		}
	})

	t.Run("tls alert", func(t *testing.T) {
		status, result := scanSSLv2(t, sslv2Server(t, []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46}))
		if status != zgrab2.SCAN_PROTOCOL_ERROR {
			t.Fatalf("expected SCAN_PROTOCOL_ERROR, got %s", status)
		}
		if result == nil || result.SSLv2 == nil {
			t.Fatalf("expected sslv2 result, got %+v", result)
		}
		if result.SSLv2.Status != zgrab2.SCAN_PROTOCOL_ERROR {
			t.Errorf("expected sslv2 status SCAN_PROTOCOL_ERROR, got %s", result.SSLv2.Status)
		}
		if result.SSLv2.Result == nil || result.SSLv2.Raw != "15030100020246" {
			t.Errorf("expected the TLS alert in raw, got %+v", result.SSLv2.Result)
		}
		if result.TLSLog != nil {
			t.Error("expected no TLS log")
		}
	})

	t.Run("connection closed", func(t *testing.T) {
		status, result := scanSSLv2(t, func(conn net.Conn) {
			// net.Pipe fails the client's write once the server has closed,
			// unlike TCP: read the CLIENT-HELLO, then close without replying.
			io.ReadFull(conn, make([]byte, 48))
		})
		if status != zgrab2.SCAN_CONNECTION_CLOSED {
			t.Fatalf("expected SCAN_CONNECTION_CLOSED, got %s", status)
		}
		if result == nil || result.SSLv2 == nil {
			t.Fatalf("expected sslv2 result, got %+v", result)
		}
		if result.SSLv2.Status != zgrab2.SCAN_CONNECTION_CLOSED {
			t.Errorf("expected sslv2 status SCAN_CONNECTION_CLOSED, got %s", result.SSLv2.Status)
		}
		if result.SSLv2.Result != nil {
			t.Errorf("expected no sslv2 reply, got %+v", result.SSLv2.Result)
		}
	})
}
