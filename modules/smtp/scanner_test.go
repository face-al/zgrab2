package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	zcryptotls "github.com/zmap/zcrypto/tls"

	"github.com/zmap/zgrab2"
)

func TestVerifySMTPContents(t *testing.T) {
	type Test struct {
		Banner         string
		ExpectedStatus zgrab2.ScanStatus
		ExpectedCode   int
	}
	testTable := map[string]Test{
		"success with code": {
			Banner: `220-some.host.com ESMTP Exim 4.93 #2 Thu, 04 Feb 2021 13:34:12 -0500
220-We do not authorize the use of this system to transport unsolicited,
220 and/or bulk e-mail.`,
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
			ExpectedCode:   0,
		},
		"success without code": {
			Banner: `ESMTP Exim 4.93 #2 Thu, 04 Feb 2021 13:34:12 -0500
220-We do not authorize the use of this system to transport unsolicited,
220 and/or bulk e-mail.`,
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
			ExpectedCode:   0,
		},
		"invalid protocol": {
			Banner:         "gibberish that doesnt match expected response",
			ExpectedStatus: zgrab2.SCAN_PROTOCOL_ERROR,
			ExpectedCode:   0,
		},
		"error response": {
			Banner:         "500-some.host.com ESMTP something went horribly wrong.",
			ExpectedStatus: zgrab2.SCAN_APPLICATION_ERROR,
			ExpectedCode:   500,
		},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			status, code := VerifySMTPContents(test.Banner)
			if status != test.ExpectedStatus {
				t.Errorf("recieved unexpected status: %s, wanted: %s", status, test.ExpectedStatus)
			}
			if code != test.ExpectedCode {
				t.Errorf("recieved unexpected code: %d, wanted: %d", code, test.ExpectedCode)
			}
		})
	}
}

// makeL4Dialer returns an L4Dialer that always returns conn.
func makeL4Dialer(conn net.Conn) func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
	return func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		}
	}
}

// generateSMTPTestCert generates a throwaway self-signed RSA certificate for
// use in TLS tests. Uses stdlib crypto so the server side can use stdlib crypto/tls.
func generateSMTPTestCert(t *testing.T) stdtls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("create TLS cert: %v", err)
	}

	return cert
}

// TestScanSMTPSHandshakeError verifies that when the TLS wrapper fails during
// an implicit-TLS (SMTPS) scan, the scanner returns SCAN_HANDSHAKE_ERROR.
func TestScanSMTPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{SMTPSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 465}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		TLSWrapper: func(_ context.Context, _ *zgrab2.ScanTarget, conn net.Conn) (*zgrab2.TLSConnection, error) {
			conn.Close()

			return nil, errors.New("tls: handshake failure")
		},
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

// TestScanSTARTTLSHandshakeError verifies that when the TLS upgrade fails
// after the STARTTLS command is accepted, the scanner returns SCAN_HANDSHAKE_ERROR.
func TestScanSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Fake SMTP server: send banner, handle EHLO, accept STARTTLS, then the
	// TLSWrapper mock will return an error before any further I/O.
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 test.example.com ESMTP\r\n"))
		serverConn.Read(buf)                                                 // EHLO
		serverConn.Write([]byte("250-test.example.com\r\n250 STARTTLS\r\n")) // advertise STARTTLS
		serverConn.Read(buf)                                                 // STARTTLS command
		serverConn.Write([]byte("220 Ready to start TLS\r\n"))
		// TLSWrapper is called next; it returns an error and we're done.
	}()

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 587}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		TLSWrapper: func(_ context.Context, _ *zgrab2.ScanTarget, conn net.Conn) (*zgrab2.TLSConnection, error) {
			return nil, errors.New("tls: handshake failure")
		},
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

// TestScanSMTPSPostTLSAppError verifies that when the TLS handshake succeeds but the
// server sends an SMTP error banner over TLS, the scanner returns
// SCAN_POST_TLS_APPLICATION_ERROR with HandshakeCompletedSuccessfully = true in TLSLog.
func TestScanSMTPSPostTLSAppError(t *testing.T) {
	cert := generateSMTPTestCert(t)
	clientConn, serverConn := net.Pipe()

	// Real TLS server: complete the handshake, then send an SMTP error banner.
	srvDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			srvDone <- err

			return
		}
		srv.Write([]byte("500 Server Error\r\n"))
		srvDone <- nil
	}()

	scanner := &Scanner{config: &Flags{SMTPSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 465}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		// Use the real TLS wrapper with InsecureSkipVerify so our self-signed
		// test cert is accepted by the zcrypto client.
		TLSWrapper: zgrab2.GetDefaultTLSWrapper(&zgrab2.BaseFlags{}, &zgrab2.TLSFlags{
			Config: &zcryptotls.Config{InsecureSkipVerify: true},
		}),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)

	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS handshake error: %v", err)
	}
	if status != zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
		t.Errorf("expected SCAN_POST_TLS_APPLICATION_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	smtpResult := result.(*ScanResults)
	if smtpResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !smtpResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true after successful TLS handshake")
	}
}

// scanSSLv2 runs an --sslv2 scan against a fake SMTP server that accepts
// STARTTLS and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 test.example.com ESMTP\r\n"))
		serverConn.Read(buf) // EHLO
		serverConn.Write([]byte("250-test.example.com\r\n250 STARTTLS\r\n"))
		serverConn.Read(buf) // STARTTLS
		serverConn.Write([]byte("220 Ready to start TLS\r\n"))
		fn(serverConn)
	}()

	scanner := &Scanner{config: &Flags{SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 587}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		TLSWrapper: func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error) {
			return nil, errors.New("TLS wrapper must not be used with --sslv2")
		},
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	smtpResult, _ := result.(*ScanResults)
	return status, smtpResult
}

func TestSSLv2UpgradeRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 test.example.com ESMTP\r\n"))
		serverConn.Read(buf) // EHLO
		serverConn.Write([]byte("250-test.example.com\r\n250 STARTTLS\r\n"))
		serverConn.Read(buf) // STARTTLS
		serverConn.Write([]byte("454 4.7.0 TLS not available\r\n"))
	}()

	scanner := &Scanner{config: &Flags{SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 587}
	dialGroup := &zgrab2.DialerGroup{L4Dialer: makeL4Dialer(clientConn), TLSWrapper: func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error) {
		return nil, errors.New("unused")
	}}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if smtpResult, _ := result.(*ScanResults); smtpResult == nil || smtpResult.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
	}
}

func TestSSLv2Validate(t *testing.T) {
	if err := (Flags{SMTPSecure: true, SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --smtps with --sslv2")
	}
	if err := (Flags{SSLv2: true}).Validate(nil); err != nil {
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
