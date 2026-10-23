package irc

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

func TestVerifyIRCContents(t *testing.T) {
	testTable := map[string]struct {
		Response       string
		ExpectedStatus zgrab2.ScanStatus
	}{
		"cap ls": {
			Response:       ":irc.example.com CAP * LS :multi-prefix tls\r\n",
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
		},
		"notices before cap ls": {
			Response:       ":irc.example.com NOTICE * :*** Looking up your hostname...\r\n:irc.example.com CAP * LS :tls\r\n",
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
		},
		"unprefixed notice": {
			Response:       "NOTICE AUTH :*** Processing connection\r\n:irc.example.com 421 * CAP :Unknown command\r\n",
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
		},
		"error": {
			Response:       "ERROR :Closing Link: 127.0.0.1 (Throttled)\r\n",
			ExpectedStatus: zgrab2.SCAN_APPLICATION_ERROR,
		},
		"smtp banner": {
			Response:       "220 mail.example.com ESMTP\r\n",
			ExpectedStatus: zgrab2.SCAN_PROTOCOL_ERROR,
		},
		"http response": {
			Response:       "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
			ExpectedStatus: zgrab2.SCAN_PROTOCOL_ERROR,
		},
		"empty": {
			Response:       "",
			ExpectedStatus: zgrab2.SCAN_PROTOCOL_ERROR,
		},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if status := VerifyIRCContents(test.Response); status != test.ExpectedStatus {
				t.Errorf("received unexpected status: %s, wanted: %s", status, test.ExpectedStatus)
			}
		})
	}
}

func TestSupportsSTARTTLS(t *testing.T) {
	testTable := map[string]struct {
		CapLS    string
		Expected bool
	}{
		"tls":                {":irc.example.com CAP * LS :multi-prefix tls sasl\r\n", true},
		"no tls":             {":irc.example.com CAP * LS :multi-prefix sasl\r\n", false},
		"empty list":         {":irc.example.com CAP * LS :\r\n", false},
		"tls on first line":  {":irc.example.com CAP * LS * :tls away-notify\r\n:irc.example.com CAP * LS :sasl\r\n", true},
		"sts is not tls":     {":irc.example.com CAP * LS :sts=port=6697\r\n", false},
		"no cap support":     {":irc.example.com 421 * CAP :Unknown command\r\n", false},
		"list without colon": {":irc.example.com CAP * LS tls\r\n", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := supportsSTARTTLS(test.CapLS); got != test.Expected {
				t.Errorf("supportsSTARTTLS(%q) = %v, wanted %v", test.CapLS, got, test.Expected)
			}
		})
	}
}

func TestCapLSEndRegex(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected bool
	}{
		"final line":               {":irc.example.com CAP * LS :multi-prefix tls\r\n", true},
		"empty list":               {":irc.example.com CAP * LS :\r\n", true},
		"continuation line":        {":irc.example.com CAP * LS * :multi-prefix\r\n", false},
		"continuation, then final": {":irc.example.com CAP * LS * :multi-prefix\r\n:irc.example.com CAP * LS :tls\r\n", true},
		"list without colon":       {":irc.example.com CAP * LS tls\r\n", false},
		"no list":                  {":irc.example.com CAP * LS\r\n", false},
		"no cap support":           {":irc.example.com 421 * CAP :Unknown command\r\n", true},
		"error":                    {"ERROR :Closing Link: 127.0.0.1 (Throttled)\r\n", true},
		"incomplete line":          {":irc.example.com CAP * LS :tls", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := capLSEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("capLSEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

// runIRCPreTLS answers CAP LS with capLS and, if startTLS is non-empty, the
// STARTTLS command with startTLS, then calls fn with serverConn so the caller
// can handle the TLS phase. Each reply is written in the given number of
// pieces to exercise reassembly. Runs in a goroutine; closes serverConn when
// done.
func runIRCPreTLS(serverConn net.Conn, capLS, startTLS string, pieces int, fn func(net.Conn)) {
	write := func(s string) {
		size := (len(s) + pieces - 1) / pieces
		for len(s) > 0 {
			n := min(size, len(s))
			serverConn.Write([]byte(s[:n]))
			s = s[n:]
		}
	}
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Read(buf) // CAP LS
		write(capLS)
		if startTLS == "" {
			return
		}
		serverConn.Read(buf) // STARTTLS
		write(startTLS)
		fn(serverConn)
	}()
}

func TestIRCSTARTTLSSuccess(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := make(chan error, 1)
	runIRCPreTLS(serverConn,
		":irc.example.com NOTICE * :*** Looking up your hostname...\r\n:irc.example.com CAP * LS * :multi-prefix\r\n:irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 670 * :STARTTLS successful, proceed with TLS handshake\r\n",
		5,
		func(conn net.Conn) {
			srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
			srvDone <- srv.Handshake()
		})

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS handshake error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s", status)
	}
	ircResult := result.(*ScanResults)
	if !strings.Contains(ircResult.CapLS, "CAP * LS :tls") {
		t.Errorf("expected complete CAP LS response, got %q", ircResult.CapLS)
	}
	if !strings.Contains(ircResult.StartTLS, " 670 ") {
		t.Errorf("expected 670 STARTTLS response, got %q", ircResult.StartTLS)
	}
	if ircResult.TLSLog == nil || ircResult.TLSLog.HandshakeLog == nil {
		t.Fatal("expected TLS log")
	}
}

func TestIRCSTARTTLSNotAdvertised(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn, ":irc.example.com CAP * LS :multi-prefix sasl\r\n", "", 1, nil)

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	ircResult := result.(*ScanResults)
	if ircResult.StartTLS != "" || ircResult.TLSLog != nil {
		t.Errorf("expected no STARTTLS attempt, got starttls=%q tls=%v", ircResult.StartTLS, ircResult.TLSLog)
	}
}

func TestIRCSTARTTLSRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 691 * :STARTTLS failed\r\n",
		1,
		func(net.Conn) {})

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if result == nil || !strings.Contains(result.(*ScanResults).StartTLS, " 691 ") {
		t.Errorf("expected 691 STARTTLS response in result, got %v", result)
	}
}

func TestIRCSTARTTLSNonstandardCode(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 679 * :STARTTLS successful, proceed with TLS handshake\r\n",
		2,
		func(net.Conn) {})

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
}

func TestIRCSTARTTLSOverride(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com 421 * CAP :Unknown command\r\n",
		":irc.example.com 670 * :STARTTLS successful, proceed with TLS handshake\r\n",
		1,
		func(net.Conn) {})

	scanner := &Scanner{config: &Flags{SendSTARTTLSOverride: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil || !strings.Contains(result.(*ScanResults).StartTLS, " 670 ") {
		t.Errorf("expected STARTTLS to be sent despite missing tls capability, got %v", result)
	}
}

func TestIRCSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 670 * :STARTTLS successful, proceed with TLS handshake\r\n",
		1,
		func(net.Conn) {})

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
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

func TestIRCNotIRC(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn, "220 mail.example.com ESMTP\r\n", "", 1, nil)

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s", status)
	}
	if result != nil {
		t.Errorf("expected nil result for non-IRC response, got %v", result)
	}
}

func TestIRCSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{IRCSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6697}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

func TestIRCValidate(t *testing.T) {
	if err := (Flags{IRCSecure: true, SendSTARTTLSOverride: true}).Validate(nil); err == nil {
		t.Error("expected error for --ircs with --send-starttls-override")
	}
	if err := (Flags{IRCSecure: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
