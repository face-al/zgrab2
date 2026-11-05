package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
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

// closeConn as a reply makes the fake server close the connection instead.
const closeConn = "close"

// scanLHLO runs a scan with --send-ehlo-override and the given
// --lhlo-fallback setting against a fake server that answers each command
// with the next reply in replies; STARTTLS, if sent, is refused with 454.
func scanLHLO(t *testing.T, fallback bool, replies ...string) (zgrab2.ScanStatus, *ScanResults, []string) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cmds := make(chan string, 8)
	go func() {
		defer serverConn.Close()
		defer close(cmds)
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 test.example.com Dovecot ready.\r\n"))
		for _, reply := range append(replies, "454 TLS not available\r\n") {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			cmds <- string(buf[:n])
			if reply == closeConn {
				return
			}
			serverConn.Write([]byte(reply))
		}
	}()

	scanner := &Scanner{config: &Flags{SendEHLOOverride: true, LHLOFallback: fallback, EHLODomain: "scanner.example.com"}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 24}
	dialGroup := &zgrab2.DialerGroup{L4Dialer: makeL4Dialer(clientConn)}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	clientConn.Close()
	var sent []string
	for cmd := range cmds {
		sent = append(sent, cmd)
	}
	smtpResult, _ := result.(*ScanResults)
	return status, smtpResult, sent
}

func TestLHLOFallback(t *testing.T) {
	const (
		ehlo     = "EHLO scanner.example.com\r\n"
		lhlo     = "LHLO scanner.example.com\r\n"
		starttls = "STARTTLS\r\n"
	)
	tests := map[string]struct {
		fallback   bool
		replies    []string
		wantSent   []string
		wantLMTP   bool
		wantLHLO   bool
		wantStatus zgrab2.ScanStatus
	}{
		"lmtp server": {
			fallback:   true,
			replies:    []string{"500 5.5.1 Unknown command\r\n", "250-test.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"},
			wantSent:   []string{ehlo, lhlo, starttls},
			wantLMTP:   true,
			wantLHLO:   true,
			wantStatus: zgrab2.SCAN_APPLICATION_ERROR, // STARTTLS refused with 454
		},
		"lmtp server, 503, keyword lower case": {
			fallback:   true,
			replies:    []string{"503 Bad sequence of commands\r\n", "250-test.example.com\r\n250 starttls\r\n"},
			wantSent:   []string{ehlo, lhlo, starttls},
			wantLMTP:   true,
			wantLHLO:   true,
			wantStatus: zgrab2.SCAN_APPLICATION_ERROR,
		},
		"lmtp server, multiline refusal, no STARTTLS": {
			fallback:   true,
			replies:    []string{"500-Unknown command\r\n500 Use LHLO\r\n", "250-test.example.com\r\n250 PIPELINING\r\n"},
			wantSent:   []string{ehlo, lhlo},
			wantLMTP:   true,
			wantLHLO:   true,
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"lmtp server, STARTTLS only in free text": {
			fallback:   true,
			replies:    []string{"500 Unknown command, no STARTTLS before LHLO\r\n", "250-STARTTLS.example.com\r\n250 PIPELINING\r\n"},
			wantSent:   []string{ehlo, lhlo},
			wantLMTP:   true,
			wantLHLO:   true,
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"smtp server": {
			fallback:   true,
			replies:    []string{"250-test.example.com\r\n250 STARTTLS\r\n"},
			wantSent:   []string{ehlo, starttls},
			wantStatus: zgrab2.SCAN_APPLICATION_ERROR,
		},
		"ehlo refused, lhlo refused": {
			fallback:   true,
			replies:    []string{"500 Unknown command\r\n", "500 Unknown command\r\n"},
			wantSent:   []string{ehlo, lhlo},
			wantLHLO:   true,
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"ehlo refused, server closes": {
			fallback:   true,
			replies:    []string{"500 Unknown command\r\n", closeConn},
			wantSent:   []string{ehlo, lhlo},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"ehlo not implemented": {
			fallback:   true,
			replies:    []string{"502 Command not implemented\r\n"},
			wantSent:   []string{ehlo},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"ehlo syntax error": {
			fallback:   true,
			replies:    []string{"501 Syntax error\r\n"},
			wantSent:   []string{ehlo},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"fallback off": {
			replies:    []string{"500 5.5.1 Unknown command\r\n"},
			wantSent:   []string{ehlo},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			status, result, sent := scanLHLO(t, test.fallback, test.replies...)
			if result == nil {
				t.Fatal("expected a result")
			}
			if len(sent) != len(test.wantSent) {
				t.Fatalf("sent %q, want %q", sent, test.wantSent)
			}
			for i := range sent {
				if sent[i] != test.wantSent[i] {
					t.Fatalf("sent %q, want %q", sent, test.wantSent)
				}
			}
			if status != test.wantStatus {
				t.Errorf("status = %v, want %v", status, test.wantStatus)
			}
			if result.LMTP != test.wantLMTP {
				t.Errorf("LMTP = %v, want %v", result.LMTP, test.wantLMTP)
			}
			if (result.LHLO != "") != test.wantLHLO {
				t.Errorf("LHLO = %q, want kept: %v", result.LHLO, test.wantLHLO)
			}
			out, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if !test.wantLMTP && bytes.Contains(out, []byte(`"lmtp"`)) {
				t.Errorf("lmtp must be omitted for a non-LMTP server: %s", out)
			}
		})
	}
}
