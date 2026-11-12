package ftp

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

func TestFTPImplicitTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{ImplicitTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 990}
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

func TestFTPAuthTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Fake FTP server: send banner, accept AUTH TLS, then the TLS wrapper fails.
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 FTP server ready\r\n"))
		serverConn.Read(buf) // AUTH TLS
		serverConn.Write([]byte("234 AUTH TLS OK\r\n"))
	}()

	scanner := &Scanner{config: &Flags{FTPAuthTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 21}
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

func TestFTPImplicitTLSHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(srv *stdtls.Conn) {
		srv.Write([]byte("220 FTP server ready\r\n"))
	})

	scanner := &Scanner{config: &Flags{ImplicitTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 990}
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
	ftpResult, ok := result.(*ScanResults)
	if !ok || ftpResult == nil {
		t.Fatal("expected non-nil *ScanResults")
	}
	if ftpResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !ftpResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

// fakeServer runs the plaintext dialog of an FTP server: banner, then each
// reply in replies to AUTH TLS and AUTH SSL in turn, then calls fn if
// afterAccept is set.
func fakeServer(serverConn net.Conn, replies []string, fn func(net.Conn)) {
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 FTP server ready\r\n"))
		for _, reply := range replies {
			serverConn.Read(buf) // AUTH TLS / AUTH SSL
			serverConn.Write([]byte(reply))
		}
		fn(serverConn)
	}()
}

func scanFTP(clientConn net.Conn, flags *Flags) (zgrab2.ScanStatus, *ScanResults) {
	scanner := &Scanner{config: flags}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 21}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	ftpResult, _ := result.(*ScanResults)
	return status, ftpResult
}

// scanSSLv2 runs an --sslv2 scan against a fake FTP server that accepts
// AUTH TLS and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	fakeServer(serverConn, []string{"234 AUTH TLS OK\r\n"}, fn)
	return scanFTP(clientConn, &Flags{FTPAuthTLS: true, SSLv2: true})
}

// TestSSLv2UpgradeAuthSSL checks the probe also runs after AUTH SSL is accepted.
func TestSSLv2UpgradeAuthSSL(t *testing.T) {
	serverHello, err := os.ReadFile("../../lib/sslv2/testdata/openssl-1.0.2u-server-hello.bin")
	if err != nil {
		t.Fatalf("reading SERVER-HELLO fixture: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	fakeServer(serverConn, []string{"504 AUTH TLS not supported\r\n", "234 AUTH SSL OK\r\n"}, sslv2Server(t, serverHello))
	status, result := scanFTP(clientConn, &Flags{FTPAuthTLS: true, SSLv2: true})
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s", status)
	}
	if result == nil || result.SSLv2 == nil || result.SSLv2.ServerHello == nil {
		t.Errorf("expected SERVER-HELLO, got %+v", result)
	}
}

// TestSSLv2UpgradeRefused: when both AUTH TLS and AUTH SSL are refused the
// scan succeeds without an upgrade, so the probe is not run.
func TestSSLv2UpgradeRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	fakeServer(serverConn, []string{"534 TLS not available\r\n", "504 SSL not available\r\n"}, func(net.Conn) {})
	status, result := scanFTP(clientConn, &Flags{FTPAuthTLS: true, SSLv2: true})
	if status != zgrab2.SCAN_SUCCESS {
		t.Errorf("expected SCAN_SUCCESS, got %s", status)
	}
	if result == nil || result.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
	}
}

func TestSSLv2Validate(t *testing.T) {
	if err := (Flags{ImplicitTLS: true, SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --implicit-tls with --sslv2")
	}
	if err := (Flags{SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --sslv2 without --authtls")
	}
	if err := (Flags{FTPAuthTLS: true, SSLv2: true}).Validate(nil); err != nil {
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
