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
	"strings"
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

// closeConn as a reply makes the fake server close the connection instead
// of answering, or after answering when it ends the reply; splitHere in a
// reply makes it send the reply in two writes.
const (
	closeConn = "<close>"
	splitHere = "<split>"
)

func TestFTPFallbackValidate(t *testing.T) {
	if err := (Flags{FTPFallback: true}).Validate(nil); err == nil {
		t.Error("expected --ftp-fallback without --send-ehlo-override to be rejected")
	}
	if err := (Flags{FTPFallback: true, SendEHLOOverride: true, SMTPSecure: true}).Validate(nil); err == nil {
		t.Error("expected --ftp-fallback with --smtps to be rejected")
	}
	if err := (Flags{FTPFallback: true, SendEHLOOverride: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// scanFTPFallback runs a scan with flags against a fake server that greets
// with greeting and answers each command with the next reply in replies.
// The TLS wrapper fails, so an accepted upgrade ends in a handshake error.
func scanFTPFallback(t *testing.T, flags Flags, greeting string, replies ...string) (zgrab2.ScanStatus, *ScanResults, []string) {
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
		serverConn.Write([]byte(greeting))
		for _, reply := range replies {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			cmds <- string(buf[:n])
			for _, part := range strings.Split(strings.TrimSuffix(reply, closeConn), splitHere) {
				serverConn.Write([]byte(part))
			}
			if strings.HasSuffix(reply, closeConn) {
				return
			}
		}
	}()

	scanner := &Scanner{config: &flags}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 21}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		TLSWrapper: func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error) {
			return nil, errors.New("handshake failed")
		},
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	clientConn.Close()
	var sent []string
	for cmd := range cmds {
		sent = append(sent, cmd)
	}
	smtpResult, _ := result.(*ScanResults)
	return status, smtpResult, sent
}

func TestFTPFallback(t *testing.T) {
	const (
		ehlo      = "EHLO scanner.example.com\r\n"
		feat      = "FEAT\r\n"
		authTLS   = "AUTH TLS\r\n"
		starttls  = "STARTTLS\r\n"
		filezilla = "220-FileZilla Server 0.9.60 beta\r\n220 Please visit https://filezilla-project.org/\r\n"
		bare      = "220 Service ready for new user.\r\n"
		features  = "211-Features:\r\n MDTM\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n"
	)
	tests := map[string]struct {
		off         bool // no --ftp-fallback
		helpAndTLS  bool // also --send-help and --send-starttls-override
		greeting    string
		replies     []string
		wantSent    []string
		wantFTP     bool
		wantFEAT    bool
		wantAuthTLS string
		wantStatus  zgrab2.ScanStatus
	}{
		"filezilla, AUTH TLS granted": {
			greeting:    filezilla,
			replies:     []string{"500 Syntax error, command unrecognized.\r\n", "234 Using authentication type TLS\r\n"},
			wantSent:    []string{ehlo, authTLS},
			wantFTP:     true,
			wantAuthTLS: "234 Using authentication type TLS\r\n",
			wantStatus:  zgrab2.SCAN_HANDSHAKE_ERROR, // the test's TLS wrapper fails
		},
		"apache ftpserver, 530 to EHLO, multiline grant": {
			greeting:    bare,
			replies:     []string{"530 Access denied.\r\n", "234-Command AUTH okay;\r\n234 starting TLS connection.\r\n"},
			wantSent:    []string{ehlo, authTLS},
			wantFTP:     true,
			wantAuthTLS: "234-Command AUTH okay;\r\n234 starting TLS connection.\r\n",
			wantStatus:  zgrab2.SCAN_HANDSHAKE_ERROR,
		},
		"grant, then nothing before the handshake": {
			helpAndTLS:  true,
			greeting:    "220-Welcome\r\n220 Service ready\r\n",
			replies:     []string{"530-Please login\r\n530 with USER and PASS.\r\n", "234 Proceed with negotiation.\r\n"},
			wantSent:    []string{ehlo, authTLS},
			wantFTP:     true,
			wantAuthTLS: "234 Proceed with negotiation.\r\n",
			wantStatus:  zgrab2.SCAN_HANDSHAKE_ERROR,
		},
		"503, FEAT in two segments, AUTH TLS retried": {
			greeting:    "220 (vsFTPd 3.0.5)\r\n",
			replies:     []string{"530 Please login with USER and PASS.\r\n", "503 Use FEAT first\r\n", "211-Features:\r\n MDTM\r\n" + splitHere + " AUTH TLS\r\n211 End\r\n", "234 Proceed with negotiation.\r\n"},
			wantSent:    []string{ehlo, authTLS, feat, authTLS},
			wantFTP:     true,
			wantFEAT:    true,
			wantAuthTLS: "234 Proceed with negotiation.\r\n",
			wantStatus:  zgrab2.SCAN_HANDSHAKE_ERROR,
		},
		"503, FEAT, closed before the retry": {
			greeting:    bare,
			replies:     []string{"500 Unknown command\r\n", "503 Use FEAT first\r\n", features + closeConn},
			wantSent:    []string{ehlo, authTLS, feat},
			wantFTP:     true,
			wantFEAT:    true,
			wantAuthTLS: "503 Use FEAT first\r\n",
			wantStatus:  zgrab2.SCAN_UNKNOWN_ERROR,
		},
		"ftp without TLS: refused, FEAT, no retry": {
			greeting:    bare,
			replies:     []string{"501 Syntax error\r\n", "534 Policy denied\r\n", "211 No features\r\n"},
			wantSent:    []string{ehlo, authTLS, feat},
			wantFTP:     true,
			wantFEAT:    true,
			wantAuthTLS: "534 Policy denied\r\n",
			wantStatus:  zgrab2.SCAN_SUCCESS,
		},
		"AUTH TLS answered with another 2xx, FEAT refused": {
			greeting:    bare,
			replies:     []string{"500 Unknown command\r\n", "200 OK\r\n", "500 Unknown command\r\n"},
			wantSent:    []string{ehlo, authTLS, feat},
			wantFEAT:    true,
			wantAuthTLS: "200 OK\r\n",
			wantStatus:  zgrab2.SCAN_SUCCESS,
		},
		"FEAT reply opening with 211 but ending with another code": {
			greeting:    bare,
			replies:     []string{"500 Unknown command\r\n", "500 Unknown command\r\n", "211-Features:\r\n MDTM\r\n500 x\r\n"},
			wantSent:    []string{ehlo, authTLS, feat},
			wantFEAT:    true,
			wantAuthTLS: "500 Unknown command\r\n",
			wantStatus:  zgrab2.SCAN_SUCCESS,
		},
		"smtp server": {
			greeting:   "220 mail.example.com ESMTP\r\n",
			replies:    []string{"250-mail.example.com\r\n250 STARTTLS\r\n", "220 Ready to start TLS\r\n"},
			wantSent:   []string{ehlo, starttls},
			wantStatus: zgrab2.SCAN_HANDSHAKE_ERROR,
		},
		"smtp server refusing EHLO": {
			greeting:    "220 mail.example.com ESMTP\r\n",
			replies:     []string{"550 Access denied\r\n", "503 5.5.1 EHLO/HELO first.\r\n", "500 5.5.2 Error: command not recognized\r\n"},
			wantSent:    []string{ehlo, authTLS, feat},
			wantFEAT:    true,
			wantAuthTLS: "503 5.5.1 EHLO/HELO first.\r\n",
			wantStatus:  zgrab2.SCAN_SUCCESS,
		},
		"ehlo refused, server closes": {
			greeting:   bare,
			replies:    []string{"500 Unknown command\r\n", closeConn},
			wantSent:   []string{ehlo, authTLS},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"ehlo refused with 4xx": {
			greeting:   bare,
			replies:    []string{"421 Too many connections\r\n"},
			wantSent:   []string{ehlo},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
		"fallback off": {
			off:        true,
			greeting:   filezilla,
			replies:    []string{"500 Syntax error, command unrecognized.\r\n"},
			wantSent:   []string{ehlo},
			wantStatus: zgrab2.SCAN_SUCCESS,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			flags := Flags{SendEHLOOverride: true, FTPFallback: !test.off, EHLODomain: "scanner.example.com",
				SendHELP: test.helpAndTLS, SendSTARTTLSOverride: test.helpAndTLS}
			status, result, sent := scanFTPFallback(t, flags, test.greeting, test.replies...)
			if result == nil {
				t.Fatal("expected a result")
			}
			if strings.Join(sent, "") != strings.Join(test.wantSent, "") {
				t.Fatalf("sent %q, want %q", sent, test.wantSent)
			}
			if status != test.wantStatus {
				t.Errorf("status = %v, want %v", status, test.wantStatus)
			}
			if result.FTP != test.wantFTP {
				t.Errorf("FTP = %v, want %v", result.FTP, test.wantFTP)
			}
			if (result.FEAT != "") != test.wantFEAT {
				t.Errorf("FEAT = %q, want kept: %v", result.FEAT, test.wantFEAT)
			}
			if result.AuthTLS != test.wantAuthTLS {
				t.Errorf("AuthTLS = %q, want %q", result.AuthTLS, test.wantAuthTLS)
			}
			if test.wantFTP && result.StartTLS != "" {
				t.Errorf("STARTTLS reply kept for an FTP server: %q", result.StartTLS)
			}
			out, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if !test.wantFTP && bytes.Contains(out, []byte(`"ftp"`)) {
				t.Errorf("ftp must be omitted for a non-FTP server: %s", out)
			}
		})
	}
}
