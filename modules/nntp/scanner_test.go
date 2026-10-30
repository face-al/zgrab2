package nntp

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"os"
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

const (
	testTransitCapabilities = "101 Capability list:\r\nVERSION 2\r\nIMPLEMENTATION INN 2.7.4\r\nIHAVE\r\nMODE-READER\r\nSTREAMING\r\n.\r\n"
	testReaderCapabilities  = "101 Capability list:\r\nVERSION 2\r\nIMPLEMENTATION INN 2.7.4\r\nREADER\r\nSTARTTLS\r\n.\r\n"
)

func TestIsModeSwitching(t *testing.T) {
	testTable := map[string]struct {
		Capabilities string
		Expected     bool
	}{
		"transit mode":              {testTransitCapabilities, true},
		"lowercase":                 {"101 Capability list:\r\nmode-reader\r\n.\r\n", true},
		"reader mode":               {testReaderCapabilities, false},
		"mode-reader and starttls":  {"101 Capability list:\r\nMODE-READER\r\nSTARTTLS\r\n.\r\n", false},
		"reader without starttls":   {"101 Capability list:\r\nVERSION 2\r\nREADER\r\n.\r\n", false},
		"two tokens, not the label": {"101 Capability list:\r\nMODE READER\r\n.\r\n", false},
		"prefix only":               {"101 Capability list:\r\nMODE-READERX\r\n.\r\n", false},
		"argument only":             {"101 Capability list:\r\nIHAVE MODE-READER\r\n.\r\n", false},
		"unknown command":           {"500 MODE-READER\r\n", false},
		"empty list":                {"101 Capability list:\r\n.\r\n", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := isModeSwitching(test.Capabilities); got != test.Expected {
				t.Errorf("isModeSwitching(%q) = %v, wanted %v", test.Capabilities, got, test.Expected)
			}
		})
	}
}

// runNNTPScript sends replies[0] as the greeting, then answers each command
// the client sends with the next reply, in order; after the last reply it
// calls fn (if non-nil) with serverConn so the caller can handle the TLS
// phase. Each reply is written in the given number of pieces. The commands
// read from the client are sent on the returned channel, which is closed when
// the server is done. Runs in a goroutine; closes serverConn when done.
func runNNTPScript(serverConn net.Conn, replies []string, pieces int, fn func(net.Conn)) <-chan string {
	commands := make(chan string, len(replies))
	write := func(s string) {
		size := (len(s) + pieces - 1) / pieces
		for len(s) > 0 {
			n := min(size, len(s))
			serverConn.Write([]byte(s[:n]))
			s = s[n:]
		}
	}
	go func() {
		defer close(commands)
		defer serverConn.Close()
		write(replies[0])
		buf := make([]byte, 512)
		for _, reply := range replies[1:] {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			commands <- strings.TrimSpace(string(buf[:n]))
			write(reply)
		}
		if fn != nil {
			fn(serverConn)
		}
	}()
	return commands
}

func collect(commands <-chan string) []string {
	var ret []string
	for c := range commands {
		ret = append(ret, c)
	}
	return ret
}

func TestNNTPModeSwitching(t *testing.T) {
	for _, pieces := range []int{1, 3} {
		cert := testhelpers.GenerateTestCert(t)
		clientConn, serverConn := net.Pipe()

		srvDone := make(chan error, 1)
		commands := runNNTPScript(serverConn, []string{
			"200 news.example.com InterNetNews server INN 2.7.4 ready (transit mode)\r\n",
			testTransitCapabilities,
			"201 news.example.com InterNetNews NNRP server INN 2.7.4 ready (no posting)\r\n",
			testReaderCapabilities,
			"382 Begin TLS negotiation now\r\n",
		}, pieces, func(conn net.Conn) {
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
		got := collect(commands)
		want := []string{"CAPABILITIES", "MODE READER", "CAPABILITIES", "STARTTLS"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("pieces=%d: expected commands %q, got %q", pieces, want, got)
		}
		nntpResult := result.(*ScanResults)
		if nntpResult.Capabilities != testTransitCapabilities {
			t.Errorf("pieces=%d: expected transit capabilities kept, got %q", pieces, nntpResult.Capabilities)
		}
		if !strings.HasPrefix(nntpResult.ModeReader, "201 ") {
			t.Errorf("pieces=%d: expected MODE READER reply, got %q", pieces, nntpResult.ModeReader)
		}
		if nntpResult.ReaderCapabilities != testReaderCapabilities {
			t.Errorf("pieces=%d: expected reader capabilities, got %q", pieces, nntpResult.ReaderCapabilities)
		}
		if !strings.HasPrefix(nntpResult.StartTLS, "382 ") {
			t.Errorf("pieces=%d: expected 382 STARTTLS response, got %q", pieces, nntpResult.StartTLS)
		}
		if nntpResult.TLSLog == nil || nntpResult.TLSLog.HandshakeLog == nil {
			t.Fatalf("pieces=%d: expected TLS log", pieces)
		}
	}
}

func TestNNTPModeReaderRefused(t *testing.T) {
	for _, reply := range []string{"502 Transit service only\r\n", "400 Service temporarily unavailable\r\n"} {
		clientConn, serverConn := net.Pipe()
		commands := runNNTPScript(serverConn, []string{"200 news.example.com ready\r\n", testTransitCapabilities, reply}, 2, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_APPLICATION_ERROR {
			t.Errorf("%q: expected SCAN_APPLICATION_ERROR, got %s", reply, status)
		}
		if got := collect(commands); len(got) != 2 || got[1] != "MODE READER" {
			t.Errorf("%q: expected CAPABILITIES then MODE READER, got %q", reply, got)
		}
		nntpResult, ok := result.(*ScanResults)
		if !ok || nntpResult.ModeReader != reply || nntpResult.ReaderCapabilities != "" || nntpResult.StartTLS != "" {
			t.Errorf("%q: expected MODE READER reply kept and nothing after it, got %+v", reply, result)
		}
	}
}

func TestNNTPModeReaderNotSent(t *testing.T) {
	testTable := map[string]struct {
		Flags        Flags
		Capabilities string
	}{
		"reader without starttls":  {Flags{}, "101 Capability list:\r\nVERSION 2\r\nREADER\r\n.\r\n"},
		"mode-reader and starttls": {Flags{}, "101 Capability list:\r\nMODE-READER\r\nSTARTTLS\r\n.\r\n"},
		"override":                 {Flags{SendSTARTTLSOverride: true}, testTransitCapabilities},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			// A third reply only answers a STARTTLS, which the first case never sends.
			commands := runNNTPScript(serverConn, []string{"200 news.example.com ready\r\n", test.Capabilities, "580 Can not initiate TLS negotiation\r\n"}, 1, nil)

			flags := test.Flags
			scanner, dialGroup, target := newTestScan(&flags, clientConn, testhelpers.MakeFailingTLSWrapper())
			_, result, _ := scanner.Scan(context.Background(), dialGroup, target)
			for _, c := range collect(commands) {
				if c == "MODE READER" {
					t.Errorf("MODE READER sent")
				}
			}
			if nntpResult, ok := result.(*ScanResults); !ok || nntpResult.ModeReader != "" || nntpResult.ReaderCapabilities != "" {
				t.Errorf("expected no MODE READER fields, got %+v", result)
			}
		})
	}
}

func TestNNTPModeReaderOnce(t *testing.T) {
	// The second list is not a reading-mode list (still MODE-READER, no
	// STARTTLS; or not a list at all): no second MODE READER, no STARTTLS.
	for _, second := range []string{testTransitCapabilities, "500 Unknown command\r\n"} {
		clientConn, serverConn := net.Pipe()
		commands := runNNTPScript(serverConn, []string{"200 news.example.com ready\r\n", testTransitCapabilities, "200 Reader mode\r\n", second}, 1, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, err := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("%q: expected SCAN_SUCCESS, got %s (%v)", second, status, err)
		}
		got := collect(commands)
		want := []string{"CAPABILITIES", "MODE READER", "CAPABILITIES"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: expected commands %q, got %q", second, want, got)
		}
		if nntpResult := result.(*ScanResults); nntpResult.ReaderCapabilities != second || nntpResult.StartTLS != "" {
			t.Errorf("%q: expected second list kept and no STARTTLS, got %+v", second, nntpResult)
		}
	}
}

func TestNNTPSecureNoModeReader(t *testing.T) {
	// MODE READER MUST NOT follow a TLS negotiation (RFC 4642, Section 5), so
	// a transit-mode list over --nntps is reported as is.
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()
	var commands []string
	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(conn *stdtls.Conn) {
		conn.Write([]byte("200 news.example.com ready (transit mode)\r\n"))
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			commands = append(commands, strings.TrimSpace(string(buf[:n])))
			conn.Write([]byte(testTransitCapabilities))
		}
	})

	scanner, dialGroup, target := newTestScan(&Flags{NNTPSecure: true}, clientConn, testhelpers.MakeInsecureTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if srvErr := <-srvDone; srvErr != nil {
		t.Fatalf("server-side TLS error: %v", srvErr)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if len(commands) != 1 || commands[0] != "CAPABILITIES" {
		t.Errorf("expected only CAPABILITIES, got %q", commands)
	}
	if nntpResult := result.(*ScanResults); nntpResult.ModeReader != "" || nntpResult.ReaderCapabilities != "" || nntpResult.StartTLS != "" {
		t.Errorf("expected no MODE READER over TLS, got %+v", nntpResult)
	}
}

// scanSSLv2 runs an --sslv2 scan against a fake NNTP server that accepts
// STARTTLS and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	runNNTPPreTLS(serverConn, "200 news.example.com ready\r\n", testCapabilities, "382 Continue with TLS negotiation\r\n", 1, fn)

	scanner, dialGroup, target := newTestScan(&Flags{SSLv2: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	nntpResult, _ := result.(*ScanResults)
	return status, nntpResult
}

func TestSSLv2UpgradeRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runNNTPPreTLS(serverConn, "200 news.example.com ready\r\n", testCapabilities, "580 Can not initiate TLS negotiation\r\n", 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{SSLv2: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if nntpResult, _ := result.(*ScanResults); nntpResult == nil || nntpResult.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
	}
}

func TestSSLv2Validate(t *testing.T) {
	if err := (Flags{NNTPSecure: true, SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --nntps with --sslv2")
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
