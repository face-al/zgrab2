package managesieve

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// runManageSievePreTLS performs the pre-STARTTLS exchange on serverConn
// (banner → CAPABILITY → STARTTLS response) and then calls fn with serverConn
// so the caller can handle the TLS phase. Runs in a goroutine; closes
// serverConn when done.
func runManageSievePreTLS(serverConn net.Conn, fn func(net.Conn)) {
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("OK\r\n"))                 // initial greeting
		serverConn.Read(buf)                               // CAPABILITY command
		serverConn.Write([]byte("\"STARTTLS\"\r\nOK\r\n")) // capabilities with STARTTLS
		serverConn.Read(buf)                               // STARTTLS command
		serverConn.Write([]byte("OK\r\n"))                 // STARTTLS accepted
		fn(serverConn)
	}()
}

func TestManageSieveSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	runManageSievePreTLS(serverConn, func(_ net.Conn) {
		// TLS wrapper will be called next and will fail; nothing to do here.
	})

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
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

func TestManageSievePostTLSCapabilitiesError(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	// Complete STARTTLS exchange and TLS handshake, then close without sending
	// post-TLS capabilities to trigger SCAN_POST_TLS_APPLICATION_ERROR.
	runManageSievePreTLS(serverConn, func(conn net.Conn) {
		srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		srv.Handshake() //nolint:errcheck // close on error is handled by defer in runManageSievePreTLS
		// Close immediately — scanner's readResponse on the TLS conn will get EOF.
	})

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
		t.Errorf("expected SCAN_POST_TLS_APPLICATION_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	msResult, ok := result.(*ScanResults)
	if !ok {
		t.Fatal("expected *ScanResults")
	}
	if msResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !msResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true after successful TLS handshake")
	}
}

func TestManageSieveHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	runManageSievePreTLS(serverConn, func(conn net.Conn) {
		srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			done <- err

			return
		}
		// Send post-TLS capabilities so the scanner reaches SCAN_SUCCESS.
		srv.Write([]byte("OK\r\n"))
		done <- nil
	})

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-done; err != nil {
		t.Fatalf("server-side TLS error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Errorf("expected SCAN_SUCCESS, got %s", status)
	}
	msResult, ok := result.(*ScanResults)
	if !ok || msResult == nil {
		t.Fatal("expected non-nil *ScanResults")
	}
	if msResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !msResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

// scanSSLv2 runs an --sslv2 scan against a fake ManageSieve server that
// accepts STARTTLS and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	runManageSievePreTLS(serverConn, fn)

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second, SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	msResult, _ := result.(*ScanResults)
	return status, msResult
}

// TestSSLv2NotAdvertised: without STARTTLS in the capabilities no upgrade is
// attempted, so the probe is not run.
func TestSSLv2NotAdvertised(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("OK\r\n"))
		serverConn.Read(buf) // CAPABILITY
		serverConn.Write([]byte("\"SIEVE\" \"fileinto\"\r\nOK\r\n"))
	}()

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second, SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_SUCCESS {
		t.Errorf("expected SCAN_SUCCESS, got %s", status)
	}
	if msResult, _ := result.(*ScanResults); msResult == nil || msResult.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
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
