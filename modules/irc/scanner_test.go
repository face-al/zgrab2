package irc

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
		"bare lf":            {":irc.example.com NOTICE * :*** Looking up your hostname...\n:irc.example.com CAP * LS :multi-prefix tls\n", true},
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
		"final line":                  {":irc.example.com CAP * LS :multi-prefix tls\r\n", true},
		"empty list":                  {":irc.example.com CAP * LS :\r\n", true},
		"continuation line":           {":irc.example.com CAP * LS * :multi-prefix\r\n", false},
		"continuation, then final":    {":irc.example.com CAP * LS * :multi-prefix\r\n:irc.example.com CAP * LS :tls\r\n", true},
		"list without colon":          {":irc.example.com CAP * LS tls\r\n", false},
		"no list":                     {":irc.example.com CAP * LS\r\n", false},
		"no cap support":              {":irc.example.com 421 * CAP :Unknown command\r\n", true},
		"error":                       {"ERROR :Closing Link: 127.0.0.1 (Throttled)\r\n", true},
		"incomplete line":             {":irc.example.com CAP * LS :tls", false},
		"notice after final line":     {":irc.example.com CAP * LS :tls\r\n:irc.example.com NOTICE * :*** Could not resolve your hostname\r\n", true},
		"notice only":                 {":irc.example.com NOTICE * :*** Looking up your hostname...\r\n", false},
		"cap ls inside notice":        {":irc.example.com NOTICE * :CAP * LS :tls\r\n", false},
		"continuation, notice, final": {":irc.example.com CAP * LS * :multi-prefix\r\n:irc.example.com NOTICE * :*** Found your hostname\r\n:irc.example.com CAP * LS :tls\r\n", true},
		"continuation, notice":        {":irc.example.com CAP * LS * :multi-prefix\r\n:irc.example.com NOTICE * :*** Found your hostname\r\n", false},
		"bare lf":                     {":irc.example.com CAP * LS :tls\n", true},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := capLSEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("capLSEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

func TestStartTLSEndRegex(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected bool
	}{
		"670":                {":irc.example.com 670 * :STARTTLS successful\r\n", true},
		"691":                {":irc.example.com 691 * :STARTTLS failed\r\n", true},
		"451":                {":irc.example.com 451 * STARTTLS :You have not registered\r\n", true},
		"error":              {"ERROR :Closing Link: 127.0.0.1\r\n", true},
		"notice after 670":   {":irc.example.com 670 * :STARTTLS successful\r\n:irc.example.com NOTICE * :*** Found your hostname\r\n", true},
		"other numeric only": {":irc.example.com 020 * :Please wait while we process your connection.\r\n", false},
		"notice only":        {":irc.example.com NOTICE * :*** Found your hostname\r\n", false},
		"incomplete line":    {":irc.example.com 670 * :STARTTLS successful", false},
		"670 inside notice":  {":irc.example.com NOTICE * :670 ok\r\n", false},
		"bare lf":            {":irc.example.com 670 * :STARTTLS successful\n", true},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := startTLSEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("startTLSEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

func TestGetIRCCode(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected int
		Error    bool
	}{
		"670":                  {Response: ":irc.example.com 670 * :STARTTLS successful\r\n", Expected: 670},
		"other numeric first":  {Response: ":irc.example.com 020 * :Please wait\r\n:irc.example.com 670 * :STARTTLS successful\r\n", Expected: 670},
		"other numeric after":  {Response: ":irc.example.com 670 * :STARTTLS successful\r\n:irc.example.com 020 * :Please wait\r\n", Expected: 670},
		"nonstandard numeric":  {Response: ":irc.example.com 679 * :STARTTLS successful\r\n", Expected: 679},
		"error without number": {Response: "ERROR :Closing Link: 127.0.0.1\r\n", Error: true},
		"no numeric":           {Response: ":irc.example.com NOTICE * :*** Found your hostname\r\n", Error: true},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			code, err := getIRCCode(test.Response)
			if (err != nil) != test.Error {
				t.Fatalf("getIRCCode(%q) error = %v, wanted error: %v", test.Response, err, test.Error)
			}
			if code != test.Expected {
				t.Errorf("getIRCCode(%q) = %d, wanted %d", test.Response, code, test.Expected)
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

// InspIRCd sends its hostname lookup result after the CAP LS reply; the scan
// must not wait for the read timeout before sending STARTTLS.
func TestIRCSTARTTLSNoticeAfterCapLS(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := make(chan error, 1)
	runIRCPreTLS(serverConn,
		":irc.local NOTICE * :*** Looking up your hostname...\r\n:irc.local CAP * LS :inspircd.org/poison tls \r\n:irc.local NOTICE * :*** Could not resolve your hostname; using your IP address instead.\r\n",
		":irc.local 670 * :STARTTLS successful, go ahead with TLS handshake\r\n",
		1, // one write: net.Pipe has no buffer for the NOTICE while we send STARTTLS
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
	if ircResult := result.(*ScanResults); !strings.Contains(ircResult.StartTLS, " 670 ") {
		t.Errorf("expected 670 STARTTLS response, got %q", ircResult.StartTLS)
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

func TestIRCSTARTTLSError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 020 * :Please wait while we process your connection.\r\nERROR :Closing Link: 127.0.0.1 (Throttled)\r\n",
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
	if result == nil || !strings.Contains(result.(*ScanResults).StartTLS, "ERROR ") {
		t.Errorf("expected ERROR in STARTTLS response, got %v", result)
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

// scanSSLv2 runs an --sslv2 scan against a fake IRC server that accepts
// STARTTLS and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 670 * :STARTTLS successful, proceed with TLS handshake\r\n",
		1, fn)

	scanner := &Scanner{config: &Flags{SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	ircResult, _ := result.(*ScanResults)
	return status, ircResult
}

func TestSSLv2UpgradeRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runIRCPreTLS(serverConn,
		":irc.example.com CAP * LS :tls\r\n",
		":irc.example.com 691 * :STARTTLS failed\r\n",
		1, func(net.Conn) {})

	scanner := &Scanner{config: &Flags{SSLv2: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if ircResult, _ := result.(*ScanResults); ircResult == nil || ircResult.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
	}
}

func TestSSLv2Validate(t *testing.T) {
	if err := (Flags{IRCSecure: true, SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --ircs with --sslv2")
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
