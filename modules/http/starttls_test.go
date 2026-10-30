package http

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

const testSwitching = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: TLS/1.0, HTTP/1.1\r\nConnection: Upgrade\r\n\r\n"

// Cases from TLS-Attacker's ReceiveRegexTextActionHttpTest.
func TestUpgradeRegexes(t *testing.T) {
	testTable := map[string]struct {
		Reply   string
		Accept  bool
		Refuse  bool
		EndRead bool
	}{
		"switching":           {testSwitching, true, false, true},
		"bare line feeds":     {"HTTP/1.1 101 Switching Protocols\nUpgrade: TLS/1.0, HTTP/1.1\n\n", true, false, true},
		"no reason":           {"HTTP/1.1 101\r\n\r\n", true, false, true},
		"no space after 101":  {"HTTP/1.1 101\n\n", false, false, false},
		"head incomplete":     {"HTTP/1.1 101 Switching Protocols\r\nUpgrade: TLS/1.0\r\n", false, false, false},
		"status line only":    {"HTTP/1.1 101", false, false, false},
		"two digits":          {"HTTP/1.1 10", false, false, false},
		"ok":                  {"HTTP/1.1 200 OK\r\nAllow: OPTIONS, GET, HEAD\r\nContent-Length: 0\r\n\r\n", false, true, true},
		"upgrade required":    {"HTTP/1.1 426 Upgrade Required\r\n", false, true, true},
		"bad request":         {"HTTP/1.1 400 Bad Request\r\n\r\n", false, true, true},
		"not implemented":     {"HTTP/1.1 501 Not Implemented\r\n\r\n", false, true, true},
		"version unsupported": {"HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n", false, true, true},
		"http/1.0 ok":         {"HTTP/1.0 200 OK\r\n\r\n", false, true, true},
		"continue":            {"HTTP/1.1 100 Continue\r\n\r\n", false, true, true},
		"early hints":         {"HTTP/1.1 103 Early Hints\r\n\r\n", false, true, true},
		"wrong last digit":    {"HTTP/1.1 109 Switching Protocols\r\n\r\n", false, true, true},
		"110":                 {"HTTP/1.1 110\r\n", false, true, true},
		"http/2 status":       {"HTTP/2 200\r\n", false, true, true},
		"tls alert":           {"\x15\x03\x01\x00\x02\x02F", false, true, true},
		"ssh banner":          {"SSH-2.0-OpenSSH_9.6\r\n", false, true, true},
		"empty":               {"", false, false, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := switchingRegex.MatchString(test.Reply); got != test.Accept {
				t.Errorf("switchingRegex.MatchString(%q) = %v, wanted %v", test.Reply, got, test.Accept)
			}
			if got := refusalRegex.MatchString(test.Reply); got != test.Refuse {
				t.Errorf("refusalRegex.MatchString(%q) = %v, wanted %v", test.Reply, got, test.Refuse)
			}
			if got := upgradeEndRegex.MatchString(test.Reply); got != test.EndRead {
				t.Errorf("upgradeEndRegex.MatchString(%q) = %v, wanted %v", test.Reply, got, test.EndRead)
			}
		})
	}
}

func TestUpgradeHost(t *testing.T) {
	testTable := map[string]struct {
		Target   zgrab2.ScanTarget
		Expected string
	}{
		"ipv4":   {zgrab2.ScanTarget{IP: net.ParseIP("192.0.2.1"), Port: 8080}, "192.0.2.1"},
		"ipv6":   {zgrab2.ScanTarget{IP: net.ParseIP("2001:db8::1")}, "[2001:db8::1]"},
		"domain": {zgrab2.ScanTarget{IP: net.ParseIP("192.0.2.1"), Domain: "example.com"}, "example.com"},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := upgradeHost(&test.Target); got != test.Expected {
				t.Errorf("upgradeHost() = %q, wanted %q", got, test.Expected)
			}
		})
	}
}

func TestValidateStartTLS(t *testing.T) {
	base := Flags{StartTLS: true, Method: "GET", Endpoint: "/"}
	testTable := map[string]struct {
		Change func(*Flags)
		Valid  bool
	}{
		"defaults":       {func(*Flags) {}, true},
		"no-http2":       {func(f *Flags) { f.NoHTTP2 = true }, true},
		"http/1.1 alpn":  {func(f *Flags) { f.NextProtos = "http/1.1" }, true},
		"use-https":      {func(f *Flags) { f.UseHTTPS = true }, false},
		"retry-https":    {func(f *Flags) { f.RetryHTTPS = true }, false},
		"no-http1.1":     {func(f *Flags) { f.NoHTTP11 = true }, false},
		"max-redirects":  {func(f *Flags) { f.MaxRedirects = 1 }, false},
		"method":         {func(f *Flags) { f.Method = "HEAD" }, false},
		"endpoint":       {func(f *Flags) { f.Endpoint = "/x" }, false},
		"request body":   {func(f *Flags) { f.RequestBody = "x" }, false},
		"custom headers": {func(f *Flags) { f.CustomHeadersNames = "a" }, false},
		"h2 alpn":        {func(f *Flags) { f.NextProtos = "h2,http/1.1" }, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			flags := base
			test.Change(&flags)
			if err := flags.Validate(nil); (err == nil) != test.Valid {
				t.Errorf("Validate() = %v, wanted valid=%v", err, test.Valid)
			}
		})
	}
}

// runStartTLS scans a fake server: serve gets the server end of a pipe after
// the upgrade request was read and checked.
func runStartTLS(t *testing.T, tlsWrapper func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error), serve func(net.Conn)) (zgrab2.ScanStatus, *Results) {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		want := "OPTIONS * HTTP/1.1\r\nHost: 192.0.2.1\r\nUpgrade: TLS/1.0\r\nConnection: Upgrade\r\n\r\n"
		got := make([]byte, len(want))
		if _, err := io.ReadFull(server, got); err != nil || string(got) != want {
			t.Errorf("upgrade request = %q, %v, wanted %q", got, err, want)
			server.Close()
			return
		}
		serve(server)
	}()

	scanner := &Scanner{}
	if err := scanner.Init(&Flags{StartTLS: true, Method: "GET", Endpoint: "/", MaxSize: 256}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	dialGroup := &zgrab2.DialerGroup{L4Dialer: testhelpers.MakeL4Dialer(client), TLSWrapper: tlsWrapper}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("192.0.2.1"), Port: 80}
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	results, _ := result.(*Results)
	return status, results
}

// writePieces writes reply in pieces of size bytes, so the reader has to
// reassemble it.
func writePieces(conn net.Conn, reply string, size int) {
	for len(reply) > 0 {
		n := min(size, len(reply))
		if _, err := conn.Write([]byte(reply[:n])); err != nil {
			return
		}
		reply = reply[n:]
	}
}

func TestScanStartTLS(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	upgradeThen := func(pieces int, overTLS string) func(net.Conn) {
		return func(conn net.Conn) {
			writePieces(conn, testSwitching, pieces)
			done := testhelpers.RunTLSServer(t, conn, cert, func(srv *stdtls.Conn) {
				srv.Write([]byte(overTLS))
			})
			if err := <-done; err != nil {
				t.Errorf("TLS server: %v", err)
			}
		}
	}
	reply := func(text string) func(net.Conn) {
		return func(conn net.Conn) {
			conn.Write([]byte(text))
			io.Copy(io.Discard, conn)
		}
	}

	testTable := map[string]struct {
		TLSWrapper func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error)
		Serve      func(net.Conn)
		Status     zgrab2.ScanStatus
		StartTLS   string
		TLS        bool
		Code       int
		Body       string
	}{
		"upgrade": {
			testhelpers.MakeInsecureTLSWrapper(), upgradeThen(len(testSwitching), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
			zgrab2.SCAN_SUCCESS, testSwitching, true, 200, "hello",
		},
		"upgrade one byte at a time": {
			testhelpers.MakeInsecureTLSWrapper(), upgradeThen(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			zgrab2.SCAN_SUCCESS, testSwitching, true, 200, "",
		},
		"interim response over tls": {
			testhelpers.MakeInsecureTLSWrapper(), upgradeThen(len(testSwitching), "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			zgrab2.SCAN_SUCCESS, testSwitching, true, 200, "",
		},
		"garbage over tls": {
			testhelpers.MakeInsecureTLSWrapper(), upgradeThen(len(testSwitching), "SSH-2.0-OpenSSH_9.6\r\n"),
			zgrab2.SCAN_POST_TLS_APPLICATION_ERROR, testSwitching, true, 0, "",
		},
		"handshake failure": {
			testhelpers.MakeFailingTLSWrapper(), reply(testSwitching),
			zgrab2.SCAN_HANDSHAKE_ERROR, testSwitching, false, 0, "",
		},
		"upgrade ignored": {
			nil, reply("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			zgrab2.SCAN_APPLICATION_ERROR, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false, 0, "",
		},
		"upgrade required on the status line": {
			nil, reply("HTTP/1.1 426 Upgrade Required\r\n"),
			zgrab2.SCAN_APPLICATION_ERROR, "HTTP/1.1 426 Upgrade Required\r\n", false, 0, "",
		},
		"wrong last digit": {
			nil, func(conn net.Conn) {
				conn.Write([]byte("HTTP/1.1 10"))
				reply("9 Switching Protocols\r\nConnection: Upgrade\r\n\r\n")(conn)
			},
			zgrab2.SCAN_APPLICATION_ERROR, "HTTP/1.1 109 Switching Protocols\r\nConnection: Upgrade\r\n\r\n", false, 0, "",
		},
		"not http": {
			nil, reply("SSH-2.0-OpenSSH_9.6\r\n"),
			zgrab2.SCAN_PROTOCOL_ERROR, "SSH-2.0-OpenSSH_9.6\r\n", false, 0, "",
		},
		"too many interim responses": {
			testhelpers.MakeInsecureTLSWrapper(), upgradeThen(len(testSwitching), strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", maxInterimResponses+1)),
			zgrab2.SCAN_POST_TLS_APPLICATION_ERROR, testSwitching, true, 100, "",
		},
		"upgrade required with body then close": {
			nil, func(conn net.Conn) {
				conn.Write([]byte("HTTP/1.1 426 Upgrade Required\r\nContent-Length: 4\r\n\r\nTLS!"))
				conn.Close()
			},
			zgrab2.SCAN_APPLICATION_ERROR, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 4\r\n\r\nTLS!", false, 0, "",
		},
		"head too long": {
			nil, reply("H" + strings.Repeat("x", upgradeReadSize)),
			zgrab2.SCAN_PROTOCOL_ERROR, "H" + strings.Repeat("x", upgradeReadSize-1), false, 0, "",
		},
		"closed": {
			nil, func(conn net.Conn) { conn.Close() },
			zgrab2.SCAN_CONNECTION_CLOSED, "", false, 0, "",
		},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			wrapper := test.TLSWrapper
			if wrapper == nil {
				wrapper = testhelpers.MakeFailingTLSWrapper()
			}
			status, results := runStartTLS(t, wrapper, test.Serve)
			if status != test.Status {
				t.Fatalf("status = %s, wanted %s", status, test.Status)
			}
			if results == nil {
				t.Fatal("no results")
			}
			if results.StartTLS != test.StartTLS {
				t.Errorf("starttls = %q, wanted %q", results.StartTLS, test.StartTLS)
			}
			if (results.TLSLog != nil) != test.TLS {
				t.Errorf("tls log present = %v, wanted %v", results.TLSLog != nil, test.TLS)
			}
			code := 0
			if results.Response != nil {
				code = results.Response.StatusCode
				if results.Response.BodyText != test.Body {
					t.Errorf("body = %q, wanted %q", results.Response.BodyText, test.Body)
				}
			}
			if code != test.Code {
				t.Errorf("response code = %d, wanted %d", code, test.Code)
			}
		})
	}
}
