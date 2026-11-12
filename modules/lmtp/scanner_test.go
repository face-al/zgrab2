package lmtp

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

const (
	testBanner = "220 lmtp.example.com Dovecot ready.\r\n"
	testLHLO   = "250-lmtp.example.com\r\n250-8BITMIME\r\n250-CHUNKING\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250 STARTTLS\r\n"
)

func TestReplyEndRegex(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected bool
	}{
		"single line":           {testBanner, true},
		"multiline":             {testLHLO, true},
		"bare code":             {"220\r\n", true},
		"bare last line":        {"250-lmtp.example.com\r\n250\r\n", true},
		"continuation only":     {"250-lmtp.example.com\r\n250-PIPELINING\r\n", false},
		"empty continuation":    {"250-\r\n", false},
		"incomplete line":       {"220 lmtp.example.com", false},
		"incomplete last line":  {"250-lmtp.example.com\r\n250 STARTTLS", false},
		"split in last code":    {"250-lmtp.example.com\r\n25", false},
		"split after last code": {"250-lmtp.example.com\r\n250", false},
		"non-lmtp line":         {"SSH-2.0-OpenSSH_9.6\r\n", true},
		"short line":            {"OK\r\n", true},
		"four digits":           {"2200 ready\r\n", true},
		"empty line":            {"\r\n", true},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := replyEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("replyEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

func TestGetLMTPCode(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Code     int
		Valid    bool
	}{
		"with text":         {"220 2.0.0 Begin TLS negotiation now.\r\n", 220, true},
		"bare code":         {"220\r\n", 220, true},
		"multiline":         {testLHLO, 250, true},
		"multiline banner":  {"220-lmtp.example.com\r\n220 ready\r\n", 220, true},
		"continuation only": {"250-lmtp.example.com\r\n", 0, false},
		"four digits":       {"2200 ready\r\n", 0, false},
		"two digits":        {"22 ready\r\n", 0, false},
		"no space":          {"220ready\r\n", 0, false},
		"ssh":               {"SSH-2.0-OpenSSH_9.6\r\n", 0, false},
		"empty":             {"", 0, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			code, err := getLMTPCode(test.Response)
			if (err == nil) != test.Valid || code != test.Code {
				t.Errorf("getLMTPCode(%q) = %d, %v, wanted %d, valid=%v", test.Response, code, err, test.Code, test.Valid)
			}
		})
	}
}

func TestSupportsSTARTTLS(t *testing.T) {
	testTable := map[string]struct {
		LHLO     string
		Expected bool
	}{
		"last line":         {testLHLO, true},
		"middle line":       {"250-lmtp.example.com\r\n250-STARTTLS\r\n250 PIPELINING\r\n", true},
		"lowercase":         {"250-lmtp.example.com\r\n250 starttls\r\n", true},
		"no starttls":       {"250-lmtp.example.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n", false},
		"domain only":       {"250 lmtp.example.com\r\n", false},
		"domain line":       {"250-STARTTLS\r\n250 PIPELINING\r\n", false},
		"greeting text":     {"250-lmtp.example.com STARTTLS\r\n250 PIPELINING\r\n", false},
		"prefix only":       {"250-lmtp.example.com\r\n250 STARTTLSX\r\n", false},
		"argument only":     {"250-lmtp.example.com\r\n250 AUTH STARTTLS\r\n", false},
		"unknown command":   {"500 5.5.1 STARTTLS\r\n", false},
		"refused":           {"250-lmtp.example.com\r\n550 STARTTLS\r\n", false},
		"not lmtp response": {"STARTTLS\r\n", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := supportsSTARTTLS(test.LHLO); got != test.Expected {
				t.Errorf("supportsSTARTTLS(%q) = %v, wanted %v", test.LHLO, got, test.Expected)
			}
		})
	}
}

func TestAddressLiteral(t *testing.T) {
	testTable := map[string]struct {
		Addr     net.Addr
		Expected string
	}{
		"ipv4":        {&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, "[192.0.2.1]"},
		"ipv4-mapped": {&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1}, "[192.0.2.1]"},
		"ipv6":        {&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}, "[IPv6:2001:db8::1]"},
		"ipv6 zone":   {&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 1, Zone: "eth0"}, "[IPv6:fe80::1]"},
		"no ip":       {&net.TCPAddr{Port: 1}, ""},
		"not tcp":     {&net.UnixAddr{Name: "/tmp/sock", Net: "unix"}, ""},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := addressLiteral(test.Addr); got != test.Expected {
				t.Errorf("addressLiteral(%v) = %q, wanted %q", test.Addr, got, test.Expected)
			}
		})
	}
}

// runLMTPPreTLS sends banner, answers LHLO with lhlo and, if startTLS is
// non-empty, the STARTTLS command with startTLS, then calls fn with
// serverConn so the caller can handle the TLS phase. Each reply is written in
// the given number of pieces to exercise reassembly. The commands received are
// sent on the returned channel, which is closed when done. Runs in a
// goroutine; closes serverConn when done.
func runLMTPPreTLS(serverConn net.Conn, banner, lhlo, startTLS string, pieces int, fn func(net.Conn)) <-chan string {
	commands := make(chan string, 2)
	write := func(s string) {
		size := (len(s) + pieces - 1) / pieces
		for len(s) > 0 {
			n := min(size, len(s))
			serverConn.Write([]byte(s[:n]))
			s = s[n:]
		}
	}
	read := func() {
		buf := make([]byte, 512)
		n, _ := serverConn.Read(buf)
		commands <- string(buf[:n])
	}
	go func() {
		defer serverConn.Close()
		defer close(commands)
		write(banner)
		if lhlo == "" {
			return
		}
		read() // LHLO
		write(lhlo)
		if startTLS == "" {
			return
		}
		read() // STARTTLS
		write(startTLS)
		fn(serverConn)
	}()
	return commands
}

func newTestScan(flags *Flags, clientConn net.Conn, tlsWrapper func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error)) (*Scanner, *zgrab2.DialerGroup, *zgrab2.ScanTarget) {
	scanner := &Scanner{config: flags}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 24, Domain: "lmtp.example.com"}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: tlsWrapper,
	}
	return scanner, dialGroup, target
}

func TestLMTPSTARTTLSSuccess(t *testing.T) {
	for _, pieces := range []int{1, 3, len(testLHLO)} {
		cert := testhelpers.GenerateTestCert(t)
		clientConn, serverConn := net.Pipe()

		srvDone := make(chan error, 1)
		commands := runLMTPPreTLS(serverConn, testBanner, testLHLO,
			"220 2.0.0 Begin TLS negotiation now.\r\n",
			pieces,
			func(conn net.Conn) {
				srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
				srvDone <- srv.Handshake()
			})

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeInsecureTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if err := <-srvDone; err != nil {
			t.Fatalf("pieces=%d: server-side TLS handshake error: %v", pieces, err)
		}
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("pieces=%d: expected SCAN_SUCCESS, got %s", pieces, status)
		}
		if got := []string{<-commands, <-commands}; got[0] != "LHLO lmtp.example.com\r\n" || got[1] != "STARTTLS\r\n" {
			t.Errorf("pieces=%d: expected LHLO and STARTTLS commands, got %q", pieces, got)
		}
		lmtpResult := result.(*ScanResults)
		if lmtpResult.Banner != testBanner {
			t.Errorf("pieces=%d: expected banner, got %q", pieces, lmtpResult.Banner)
		}
		if lmtpResult.LHLO != testLHLO {
			t.Errorf("pieces=%d: expected complete LHLO response, got %q", pieces, lmtpResult.LHLO)
		}
		if !strings.HasPrefix(lmtpResult.StartTLS, "220 ") {
			t.Errorf("pieces=%d: expected 220 STARTTLS response, got %q", pieces, lmtpResult.StartTLS)
		}
		if lmtpResult.TLSLog == nil || lmtpResult.TLSLog.HandshakeLog == nil {
			t.Fatalf("pieces=%d: expected TLS log", pieces)
		}
	}
}

func TestLMTPLHLODomain(t *testing.T) {
	testTable := map[string]struct {
		Flag     string
		Domain   string
		Expected string
	}{
		"flag":          {"client.example.com", "lmtp.example.com", "LHLO client.example.com\r\n"},
		"target domain": {"", "lmtp.example.com", "LHLO lmtp.example.com\r\n"},
		// net.Pipe has no IP address, so there is no address literal either.
		"no domain": {"", "", "LHLO\r\n"},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			commands := runLMTPPreTLS(serverConn, testBanner, "250 lmtp.example.com\r\n", "", 1, nil)

			scanner, dialGroup, target := newTestScan(&Flags{LHLODomain: test.Flag}, clientConn, testhelpers.MakeFailingTLSWrapper())
			target.Domain = test.Domain
			status, _, err := scanner.Scan(context.Background(), dialGroup, target)
			if status != zgrab2.SCAN_SUCCESS {
				t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
			}
			if got := <-commands; got != test.Expected {
				t.Errorf("expected %q, got %q", test.Expected, got)
			}
		})
	}
}

func TestLMTPLHLOAddressLiteral(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	commands := runLMTPPreTLS(serverConn, testBanner, "250 lmtp.example.com\r\n", "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	target.Domain = ""
	status, _, err := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if got := <-commands; got != "LHLO [127.0.0.1]\r\n" {
		t.Errorf("expected LHLO with address literal, got %q", got)
	}
}

func TestLMTPSTARTTLSNotAdvertised(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLMTPPreTLS(serverConn, testBanner,
		"250-lmtp.example.com\r\n250-PIPELINING\r\n250 ENHANCEDSTATUSCODES\r\n", "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	lmtpResult := result.(*ScanResults)
	if lmtpResult.StartTLS != "" || lmtpResult.TLSLog != nil {
		t.Errorf("expected no STARTTLS attempt, got starttls=%q tls=%v", lmtpResult.StartTLS, lmtpResult.TLSLog)
	}
}

func TestLMTPLHLORefused(t *testing.T) {
	testTable := map[string]string{
		"smtp server":    "500 5.5.1 Unknown command\r\n",
		"syntax error":   "501 Missing hostname\r\n",
		"not available":  "421 4.3.2 Service shutting down\r\n",
		"other 2xx code": "251 lmtp.example.com\r\n",
	}

	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runLMTPPreTLS(serverConn, testBanner, reply, "", 2, nil)

			scanner, dialGroup, target := newTestScan(&Flags{SendSTARTTLSOverride: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
			status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
			if status != zgrab2.SCAN_APPLICATION_ERROR {
				t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
			}
			if result == nil || result.(*ScanResults).LHLO != reply || result.(*ScanResults).StartTLS != "" {
				t.Errorf("expected LHLO response %q in result and no STARTTLS, got %v", reply, result)
			}
		})
	}
}

func TestLMTPSTARTTLSRefused(t *testing.T) {
	testTable := map[string]string{
		"tls not available": "454 4.7.0 TLS not available\r\n",
		"not enabled":       "502 5.5.1 TLS support is not enabled.\r\n",
		"discovery refusal": "503 5.5.1 Error: send LHLO first\r\n",
		"syntax error":      "501 5.5.4 Syntax: STARTTLS\r\n",
		"badsplit":          "229 2.0.0 Ready to start TLS\r\n",
		"nonstd":            "999 2.0.0 Ready to start TLS\r\n",
	}

	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runLMTPPreTLS(serverConn, testBanner, testLHLO, reply, 2, func(net.Conn) {})

			scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
			status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
			if status != zgrab2.SCAN_APPLICATION_ERROR {
				t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
			}
			if result == nil || result.(*ScanResults).StartTLS != reply {
				t.Errorf("expected STARTTLS response %q in result, got %v", reply, result)
			}
		})
	}
}

func TestLMTPSTARTTLSOverride(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLMTPPreTLS(serverConn, testBanner, "250 lmtp.example.com\r\n", "220\r\n", 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{SendSTARTTLSOverride: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil || result.(*ScanResults).StartTLS != "220\r\n" {
		t.Errorf("expected STARTTLS to be sent despite missing keyword, got %v", result)
	}
}

func TestLMTPSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLMTPPreTLS(serverConn, testBanner, testLHLO, "220 2.0.0 Ready to start TLS\r\n", 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestLMTPServiceUnavailable(t *testing.T) {
	for _, banner := range []string{"421 4.3.2 Service not available\r\n", "554 5.7.1 No service for you\r\n", "554-No service\r\n554 for you\r\n", "550 Access denied\r\n", "450 Try later\r\n"} {
		clientConn, serverConn := net.Pipe()
		runLMTPPreTLS(serverConn, banner, "", "", 1, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_APPLICATION_ERROR {
			t.Errorf("%q: expected SCAN_APPLICATION_ERROR, got %s", banner, status)
		}
		if result == nil || result.(*ScanResults).Banner != banner {
			t.Errorf("%q: expected banner in result, got %v", banner, result)
		}
	}
}

func TestLMTPNotLMTP(t *testing.T) {
	for _, banner := range []string{"SSH-2.0-OpenSSH_9.6\r\n", "200 news.example.com ready\r\n", "HTTP/1.1 400 Bad Request\r\n", "+OK POP3 ready\r\n", "354 Start mail input\r\n", "600 Unknown\r\n"} {
		clientConn, serverConn := net.Pipe()
		runLMTPPreTLS(serverConn, banner, "", "", 1, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_PROTOCOL_ERROR {
			t.Errorf("%q: expected SCAN_PROTOCOL_ERROR, got %s", banner, status)
		}
		if result != nil {
			t.Errorf("%q: expected nil result for non-LMTP response, got %v", banner, result)
		}
	}
}

func TestLMTPSecure(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()
	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(conn *stdtls.Conn) {
		conn.Write([]byte(testBanner))
		buf := make([]byte, 512)
		conn.Read(buf) // LHLO
		// Even if listed over TLS, which RFC 3207, Section 4.2 forbids, STARTTLS must not be sent.
		conn.Write([]byte(testLHLO))
	})

	scanner, dialGroup, target := newTestScan(&Flags{LMTPSecure: true}, clientConn, testhelpers.MakeInsecureTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if srvErr := <-srvDone; srvErr != nil {
		t.Fatalf("server-side TLS error: %v", srvErr)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	lmtpResult := result.(*ScanResults)
	if !lmtpResult.ImplicitTLS || lmtpResult.TLSLog == nil || lmtpResult.StartTLS != "" {
		t.Errorf("expected implicit TLS without STARTTLS, got %+v", lmtpResult)
	}
	if lmtpResult.Banner != testBanner || lmtpResult.LHLO != testLHLO {
		t.Errorf("expected banner and LHLO read over TLS, got %+v", lmtpResult)
	}
}

func TestLMTPSecureRefused(t *testing.T) {
	testTable := map[string]struct {
		Banner string
		LHLO   string
	}{
		"greeting": {"554 5.7.1 No service for you\r\n", ""},
		"lhlo":     {testBanner, "500 5.5.1 Unknown command\r\n"},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			cert := testhelpers.GenerateTestCert(t)
			clientConn, serverConn := net.Pipe()
			srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(conn *stdtls.Conn) {
				conn.Write([]byte(test.Banner))
				if test.LHLO == "" {
					return
				}
				buf := make([]byte, 512)
				conn.Read(buf) // LHLO
				conn.Write([]byte(test.LHLO))
			})

			scanner, dialGroup, target := newTestScan(&Flags{LMTPSecure: true}, clientConn, testhelpers.MakeInsecureTLSWrapper())
			status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
			if srvErr := <-srvDone; srvErr != nil {
				t.Fatalf("server-side TLS error: %v", srvErr)
			}
			if status != zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
				t.Errorf("expected SCAN_POST_TLS_APPLICATION_ERROR, got %s", status)
			}
			if result == nil || result.(*ScanResults).TLSLog == nil || result.(*ScanResults).Banner != test.Banner {
				t.Errorf("expected banner and TLS log in result, got %v", result)
			}
		})
	}
}

func TestLMTPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner, dialGroup, target := newTestScan(&Flags{LMTPSecure: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestValidate(t *testing.T) {
	if err := (Flags{LMTPSecure: true, SendSTARTTLSOverride: true}).Validate(nil); err == nil {
		t.Error("expected error for --lmtps with --send-starttls-override")
	}
	if err := (Flags{LMTPSecure: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
