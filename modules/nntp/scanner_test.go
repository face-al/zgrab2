package nntp

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

const testCapabilities = "101 Capability list:\r\nVERSION 2\r\nREADER\r\nSTARTTLS\r\nLIST ACTIVE NEWSGROUPS\r\n.\r\n"

func TestCapabilitiesEndRegex(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected bool
	}{
		"capability list":     {testCapabilities, true},
		"empty list":          {"101 Capability list:\r\n.\r\n", true},
		"bare 101":            {"101\r\n.\r\n", true},
		"status line only":    {"101 Capability list:\r\n", false},
		"bare status line":    {"101\r\n", false},
		"list not terminated": {"101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n", false},
		"dot-stuffed line":    {"101 Capability list:\r\n..\r\n", false},
		"label ending in dot": {"101 Capability list:\r\nVERSION.\r\n", false},
		"incomplete dot line": {"101 Capability list:\r\nVERSION 2\r\n.", false},
		"unknown command":     {"500 Unknown command\r\n", true},
		"mode reader needed":  {"401 MODE-READER\r\n", true},
		"other 1xx":           {"111 20260626000000\r\n", true},
		"incomplete line":     {"500 Unknown command", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := capabilitiesEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("capabilitiesEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

func TestSupportsSTARTTLS(t *testing.T) {
	testTable := map[string]struct {
		Capabilities string
		Expected     bool
	}{
		"starttls":             {testCapabilities, true},
		"lowercase":            {"101 Capability list:\r\nVERSION 2\r\nstarttls\r\n.\r\n", true},
		"with arguments":       {"101 Capability list:\r\nSTARTTLS foo\r\n.\r\n", true},
		"tab separated":        {"101 Capability list:\r\nSTARTTLS\tfoo\r\n.\r\n", true},
		"no starttls":          {"101 Capability list:\r\nVERSION 2\r\nREADER\r\n.\r\n", false},
		"empty list":           {"101 Capability list:\r\n.\r\n", false},
		"prefix only":          {"101 Capability list:\r\nSTARTTLSX\r\n.\r\n", false},
		"argument only":        {"101 Capability list:\r\nAUTHINFO STARTTLS\r\n.\r\n", false},
		"dot-stuffed":          {"101 Capability list:\r\n..STARTTLS\r\n.\r\n", false},
		"in status line":       {"101 STARTTLS supported\r\nVERSION 2\r\n.\r\n", false},
		"unknown command":      {"500 STARTTLS\r\n", false},
		"after list":           {"101 Capability list:\r\nVERSION 2\r\n.\r\nSTARTTLS\r\n", false},
		"transit mode (innd)":  {"101 Capability list:\r\nVERSION 2\r\nIHAVE\r\nMODE-READER\r\n.\r\n", false},
		"not an nntp response": {"STARTTLS\r\n", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := supportsSTARTTLS(test.Capabilities); got != test.Expected {
				t.Errorf("supportsSTARTTLS(%q) = %v, wanted %v", test.Capabilities, got, test.Expected)
			}
		})
	}
}

func TestGetNNTPCode(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Code     int
		Valid    bool
	}{
		"with text":   {"382 Continue with TLS negotiation\r\n", 382, true},
		"bare code":   {"382\r\n", 382, true},
		"greeting":    {"201 news.example.com ready (no posting)\r\n", 201, true},
		"four digits": {"3820 Continue\r\n", 0, false},
		"two digits":  {"38 Continue\r\n", 0, false},
		"no space":    {"382Continue\r\n", 0, false},
		"smtp banner": {"220-mail.example.com ESMTP\r\n", 0, false},
		"http":        {"HTTP/1.1 400 Bad Request\r\n", 0, false},
		"empty":       {"", 0, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			code, err := getNNTPCode(test.Response)
			if (err == nil) != test.Valid || code != test.Code {
				t.Errorf("getNNTPCode(%q) = %d, %v, wanted %d, valid=%v", test.Response, code, err, test.Code, test.Valid)
			}
		})
	}
}

// runNNTPPreTLS sends banner, answers CAPABILITIES with capabilities and, if
// startTLS is non-empty, the STARTTLS command with startTLS, then calls fn
// with serverConn so the caller can handle the TLS phase. Each reply is
// written in the given number of pieces to exercise reassembly. Runs in a
// goroutine; closes serverConn when done.
func runNNTPPreTLS(serverConn net.Conn, banner, capabilities, startTLS string, pieces int, fn func(net.Conn)) {
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
		write(banner)
		if capabilities == "" {
			return
		}
		buf := make([]byte, 512)
		serverConn.Read(buf) // CAPABILITIES
		write(capabilities)
		if startTLS == "" {
			return
		}
		serverConn.Read(buf) // STARTTLS
		write(startTLS)
		fn(serverConn)
	}()
}

func newTestScan(flags *Flags, clientConn net.Conn, tlsWrapper func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error)) (*Scanner, *zgrab2.DialerGroup, *zgrab2.ScanTarget) {
	scanner := &Scanner{config: flags}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 119}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: tlsWrapper,
	}
	return scanner, dialGroup, target
}

func TestNNTPSTARTTLSSuccess(t *testing.T) {
	for _, pieces := range []int{1, 3, len(testCapabilities)} {
		cert := testhelpers.GenerateTestCert(t)
		clientConn, serverConn := net.Pipe()

		srvDone := make(chan error, 1)
		runNNTPPreTLS(serverConn,
			"200 news.example.com InterNetNews NNRP server INN 2.7.4 ready (posting ok)\r\n",
			testCapabilities,
			"382 Continue with TLS negotiation\r\n",
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
		nntpResult := result.(*ScanResults)
		if !strings.HasPrefix(nntpResult.Banner, "200 ") {
			t.Errorf("pieces=%d: expected banner, got %q", pieces, nntpResult.Banner)
		}
		if nntpResult.Capabilities != testCapabilities {
			t.Errorf("pieces=%d: expected complete CAPABILITIES response, got %q", pieces, nntpResult.Capabilities)
		}
		if !strings.HasPrefix(nntpResult.StartTLS, "382 ") {
			t.Errorf("pieces=%d: expected 382 STARTTLS response, got %q", pieces, nntpResult.StartTLS)
		}
		if nntpResult.TLSLog == nil || nntpResult.TLSLog.HandshakeLog == nil {
			t.Fatalf("pieces=%d: expected TLS log", pieces)
		}
	}
}

func TestNNTPSTARTTLSNotAdvertised(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runNNTPPreTLS(serverConn, "201 news.example.com ready (no posting)\r\n",
		"101 Capability list:\r\nVERSION 2\r\nREADER\r\n.\r\n", "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	nntpResult := result.(*ScanResults)
	if nntpResult.StartTLS != "" || nntpResult.TLSLog != nil {
		t.Errorf("expected no STARTTLS attempt, got starttls=%q tls=%v", nntpResult.StartTLS, nntpResult.TLSLog)
	}
}

func TestNNTPNoCapabilitiesCommand(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runNNTPPreTLS(serverConn, "200 news.example.com ready\r\n", "500 What?\r\n", "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if nntpResult := result.(*ScanResults); nntpResult.Capabilities != "500 What?\r\n" || nntpResult.StartTLS != "" {
		t.Errorf("expected 500 reply kept and no STARTTLS, got %+v", nntpResult)
	}
}

func TestNNTPSTARTTLSRefused(t *testing.T) {
	testTable := map[string]string{
		"tls not available": "580 Can not initiate TLS negotiation\r\n",
		"already tls":       "502 Command unavailable\r\n",
		"discovery refusal": "401 CAPABILITIES Send CAPABILITIES before STARTTLS\r\n",
		"badsplit":          "389 Continue with TLS negotiation\r\n",
		"nonstd":            "999 Continue with TLS negotiation\r\n",
	}

	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runNNTPPreTLS(serverConn, "200 news.example.com ready\r\n", testCapabilities, reply, 2, func(net.Conn) {})

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

func TestNNTPSTARTTLSOverride(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runNNTPPreTLS(serverConn, "200 news.example.com ready\r\n", "500 What?\r\n", "382\r\n", 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{SendSTARTTLSOverride: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil || result.(*ScanResults).StartTLS != "382\r\n" {
		t.Errorf("expected STARTTLS to be sent despite missing capability, got %v", result)
	}
}

func TestNNTPSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runNNTPPreTLS(serverConn, "200 news.example.com ready\r\n", testCapabilities,
		"382 Continue with TLS negotiation\r\n", 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestNNTPServiceUnavailable(t *testing.T) {
	for _, banner := range []string{"400 Service temporarily unavailable\r\n", "502 You have no permission to talk.  Goodbye!\r\n"} {
		clientConn, serverConn := net.Pipe()
		runNNTPPreTLS(serverConn, banner, "", "", 1, nil)

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

func TestNNTPNotNNTP(t *testing.T) {
	for _, banner := range []string{"SSH-2.0-OpenSSH_9.6\r\n", "220 mail.example.com ESMTP\r\n", "382 Continue with TLS negotiation\r\n"} {
		clientConn, serverConn := net.Pipe()
		runNNTPPreTLS(serverConn, banner, "", "", 1, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_PROTOCOL_ERROR {
			t.Errorf("%q: expected SCAN_PROTOCOL_ERROR, got %s", banner, status)
		}
		if result != nil {
			t.Errorf("%q: expected nil result for non-NNTP response, got %v", banner, result)
		}
	}
}

func TestNNTPSecure(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()
	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(conn *stdtls.Conn) {
		conn.Write([]byte("200 news.example.com ready\r\n"))
		buf := make([]byte, 512)
		conn.Read(buf) // CAPABILITIES
		conn.Write([]byte("101 Capability list:\r\nVERSION 2\r\nREADER\r\n.\r\n"))
	})

	scanner, dialGroup, target := newTestScan(&Flags{NNTPSecure: true}, clientConn, testhelpers.MakeInsecureTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if srvErr := <-srvDone; srvErr != nil {
		t.Fatalf("server-side TLS error: %v", srvErr)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	nntpResult := result.(*ScanResults)
	if !nntpResult.ImplicitTLS || nntpResult.TLSLog == nil || nntpResult.StartTLS != "" {
		t.Errorf("expected implicit TLS without STARTTLS, got %+v", nntpResult)
	}
}

func TestNNTPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner, dialGroup, target := newTestScan(&Flags{NNTPSecure: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestValidate(t *testing.T) {
	if err := (Flags{NNTPSecure: true, SendSTARTTLSOverride: true}).Validate(nil); err == nil {
		t.Error("expected error for --nntps with --send-starttls-override")
	}
	if err := (Flags{NNTPSecure: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
