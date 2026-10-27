package xmpp

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

const (
	testHeader = "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'" +
		" xml:lang='en' from='xmpp.example.com' id='4a0f' version='1.0'>"
	testFeatures = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>" +
		"<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>262144</max-bytes></limits></stream:features>"
	testOpening = "<?xml version='1.0'?><stream:stream to='xmpp.example.com' version='1.0' xmlns='jabber:client'" +
		" xmlns:stream='http://etherx.jabber.org/streams'>"
	testProceed = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
)

func TestOpeningEndRegex(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected bool
	}{
		"features":              {testHeader + testFeatures, true},
		"empty features":        {testHeader + "<stream:features/>", true},
		"empty features spaced": {testHeader + "<stream:features />", true},
		"features with newline": {testHeader + "<stream:features>\n<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n</stream:features>", true},
		"header only":           {testHeader, false},
		"features incomplete":   {testHeader + "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", false},
		"stream error":          {testHeader + "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", true},
		"stream error open":     {testHeader + "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>", false},
		"empty stream error":    {testHeader + "<stream:error/>", true},
		"stream closed":         {testHeader + "</stream:stream>", true},
		"other prefix":          {"<str:stream xmlns:str='http://etherx.jabber.org/streams'><str:features/>", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := openingEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("openingEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

func TestUpgradeEndRegex(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected bool
	}{
		"proceed":              {testProceed, true},
		"proceed with end tag": {"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'></proceed>", true},
		"proceed incomplete":   {"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'", false},
		"failure":              {"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", true},
		"failure with content": {"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'>\n<text>no</text>\n</failure>", true},
		"failure open":         {"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'>\n<text>no</text>", false},
		"stream error":         {"<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", true},
		"stream closed":        {"</stream:stream>", true},
		"badsplit":             {"<proceee xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", false},
		"nonstd":               {"<success xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := upgradeEndRegex.MatchString(test.Response); got != test.Expected {
				t.Errorf("upgradeEndRegex.MatchString(%q) = %v, wanted %v", test.Response, got, test.Expected)
			}
		})
	}
}

func TestStarttlsFeature(t *testing.T) {
	testTable := map[string]struct {
		Features   string
		Advertised bool
		Required   bool
	}{
		"required":        {testFeatures, true, true},
		"optional":        {"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>", true, false},
		"optional empty":  {"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'></starttls></stream:features>", true, false},
		"double quotes":   {`<stream:features><starttls xmlns = "urn:ietf:params:xml:ns:xmpp-tls"><required/></starttls></stream:features>`, true, true},
		"newlines":        {"<stream:features>\n  <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>\n    <required/>\n  </starttls>\n</stream:features>", true, true},
		"other required":  {"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><required/></bind></stream:features>", true, false},
		"other namespace": {"<stream:features><starttls xmlns='urn:example:starttls'/></stream:features>", false, false},
		"no namespace":    {"<stream:features><starttls/></stream:features>", false, false},
		"none":            {"<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>", false, false},
		"empty":           {"<stream:features/>", false, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			match := starttlsFeatureRegex.FindStringSubmatch(test.Features)
			if advertised := match != nil; advertised != test.Advertised {
				t.Fatalf("advertised(%q) = %v, wanted %v", test.Features, advertised, test.Advertised)
			}
			if match != nil {
				if required := requiredRegex.MatchString(match[1]); required != test.Required {
					t.Errorf("required(%q) = %v, wanted %v", test.Features, required, test.Required)
				}
			}
		})
	}
}

func TestGetStreamError(t *testing.T) {
	testTable := map[string]struct {
		Response string
		Expected string
	}{
		"host-unknown":   {testHeader + "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>", "host-unknown"},
		"text first":     {"<stream:error><text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>bad</text><improper-addressing xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", "improper-addressing"},
		"text after":     {"<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>This server does not serve 127.0.0.1</text></stream:error>", "host-unknown"},
		"no namespace":   {"<stream:error><host-unknown/></stream:error>", "host-unknown"},
		"unterminated":   {"<stream:error><see-other-host xmlns='urn:ietf:params:xml:ns:xmpp-streams'>", "see-other-host"},
		"self-closing":   {"<stream:error/>", "unknown"},
		"text only":      {"<stream:error><text>bye</text></stream:error>", "unknown"},
		"no error":       {testHeader + testFeatures, ""},
		"stream closed":  {testHeader + "</stream:stream>", ""},
		"failure":        {"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>", ""},
		"prefixed":       {"<stream:error><err:host-unknown xmlns:err='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", "host-unknown"},
		"prefixed text":  {"<stream:error><streams:text xmlns:streams='urn:ietf:params:xml:ns:xmpp-streams'>bye</streams:text><streams:conflict xmlns:streams='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", "conflict"},
		"other elements": {"<stream:error>\n  <conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>\n</stream:error>", "conflict"},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			if got := getStreamError(test.Response); got != test.Expected {
				t.Errorf("getStreamError(%q) = %q, wanted %q", test.Response, got, test.Expected)
			}
		})
	}
}

// runXMPPPreTLS reads the opening stream header, answers it with opening and,
// if startTLS is non-empty, the STARTTLS command with startTLS, then calls fn
// with serverConn so the caller can handle the TLS phase. Each reply is
// written in the given number of pieces to exercise reassembly. The data
// received is sent on the returned channel, which is closed when done. Runs in
// a goroutine; closes serverConn when done.
func runXMPPPreTLS(serverConn net.Conn, opening, startTLS string, pieces int, fn func(net.Conn)) <-chan string {
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
		read() // opening stream header
		write(opening)
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
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5222, Domain: "xmpp.example.com"}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: tlsWrapper,
	}
	return scanner, dialGroup, target
}

func TestXMPPSTARTTLSSuccess(t *testing.T) {
	for _, proceed := range []string{testProceed, "<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"></proceed>"} {
		for _, pieces := range []int{1, 3, len(testHeader + testFeatures)} {
			cert := testhelpers.GenerateTestCert(t)
			clientConn, serverConn := net.Pipe()

			srvDone := make(chan error, 1)
			commands := runXMPPPreTLS(serverConn, testHeader+testFeatures, proceed, pieces,
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
			if got := []string{<-commands, <-commands}; got[0] != testOpening || got[1] != commandSTARTTLS {
				t.Errorf("pieces=%d: expected opening and STARTTLS, got %q", pieces, got)
			}
			xmppResult := result.(*ScanResults)
			if xmppResult.Banner != testHeader+testFeatures || xmppResult.Features != testFeatures {
				t.Errorf("pieces=%d: expected banner and features, got %+v", pieces, xmppResult)
			}
			if !xmppResult.STARTTLSRequired {
				t.Errorf("pieces=%d: expected starttls_required", pieces)
			}
			if xmppResult.StartTLS != proceed {
				t.Errorf("pieces=%d: expected proceed, got %q", pieces, xmppResult.StartTLS)
			}
			if xmppResult.TLSLog == nil || xmppResult.TLSLog.HandshakeLog == nil {
				t.Fatalf("pieces=%d: expected TLS log", pieces)
			}
		}
	}
}

func TestXMPPDomain(t *testing.T) {
	testTable := map[string]struct {
		Flag     string
		Domain   string
		Expected string
	}{
		"flag":          {"chat.example.org", "xmpp.example.com", "chat.example.org"},
		"target domain": {"", "xmpp.example.com", "xmpp.example.com"},
		"ip address":    {"", "", "127.0.0.1"},
		"escaped":       {"a'b&c<d", "", "a&apos;b&amp;c&lt;d"},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			commands := runXMPPPreTLS(serverConn, testHeader+"<stream:features/>", "", 1, nil)

			scanner, dialGroup, target := newTestScan(&Flags{XMPPDomain: test.Flag}, clientConn, testhelpers.MakeFailingTLSWrapper())
			target.Domain = test.Domain
			status, _, err := scanner.Scan(context.Background(), dialGroup, target)
			if status != zgrab2.SCAN_SUCCESS {
				t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
			}
			expected := "<?xml version='1.0'?><stream:stream to='" + test.Expected + "' version='1.0' xmlns='jabber:client'" +
				" xmlns:stream='http://etherx.jabber.org/streams'>"
			if got := <-commands; got != expected {
				t.Errorf("expected %q, got %q", expected, got)
			}
		})
	}
}

func TestXMPPDomainSNI(t *testing.T) {
	testTable := map[string]struct {
		Flags    Flags
		Expected string
	}{
		"domain":      {Flags{XMPPDomain: "chat.example.org"}, "chat.example.org"},
		"server name": {Flags{XMPPDomain: "chat.example.org", TLSFlags: zgrab2.TLSFlags{ServerName: "tls.example.org"}}, "tls.example.org"},
		"no sni":      {Flags{XMPPDomain: "chat.example.org", TLSFlags: zgrab2.TLSFlags{NoSNI: true}}, ""},
		"no domain":   {Flags{}, ""},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			flags := test.Flags
			var scanner Scanner
			if err := scanner.Init(&flags); err != nil {
				t.Fatalf("Init: %v", err)
			}
			if flags.ServerName != test.Expected {
				t.Errorf("expected server name %q, got %q", test.Expected, flags.ServerName)
			}
		})
	}
}

func TestXMPPSTARTTLSNotAdvertised(t *testing.T) {
	for _, features := range []string{"<stream:features/>", "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>"} {
		clientConn, serverConn := net.Pipe()
		runXMPPPreTLS(serverConn, testHeader+features, "", 2, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, err := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("%q: expected SCAN_SUCCESS, got %s (%v)", features, status, err)
		}
		xmppResult := result.(*ScanResults)
		if xmppResult.Features != features || xmppResult.StartTLS != "" || xmppResult.TLSLog != nil {
			t.Errorf("%q: expected features and no STARTTLS attempt, got %+v", features, xmppResult)
		}
	}
}

func TestXMPPStreamError(t *testing.T) {
	testTable := map[string]struct {
		Reply     string
		Condition string
	}{
		"host-unknown":        {testHeader + "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>", "host-unknown"},
		"improper-addressing": {testHeader + "<stream:error><improper-addressing xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Missing to</text></stream:error></stream:stream>", "improper-addressing"},
		"self-closing":        {testHeader + "<stream:error/>", "unknown"},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runXMPPPreTLS(serverConn, test.Reply, "", 2, nil)

			scanner, dialGroup, target := newTestScan(&Flags{SendSTARTTLSOverride: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
			status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
			if status != zgrab2.SCAN_APPLICATION_ERROR {
				t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			xmppResult := result.(*ScanResults)
			if xmppResult.Banner != test.Reply || xmppResult.StreamError != test.Condition || xmppResult.StartTLS != "" {
				t.Errorf("expected banner, stream error %q and no STARTTLS, got %+v", test.Condition, xmppResult)
			}
		})
	}
}

func TestXMPPNoFeatures(t *testing.T) {
	// A pre-1.0 header (no version) gets no features (RFC 6120, Section
	// 4.7.5): the server then sends nothing more, or closes the stream.
	for _, reply := range []string{testHeader, testHeader + "</stream:stream>"} {
		clientConn, serverConn := net.Pipe()
		runXMPPPreTLS(serverConn, reply, "", 1, nil)

		scanner, dialGroup, target := newTestScan(&Flags{SendSTARTTLSOverride: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_APPLICATION_ERROR {
			t.Errorf("%q: expected SCAN_APPLICATION_ERROR, got %s", reply, status)
		}
		if result == nil || result.(*ScanResults).Banner != reply || result.(*ScanResults).StartTLS != "" {
			t.Errorf("%q: expected banner in result and no STARTTLS, got %v", reply, result)
		}
	}
}

func TestXMPPSTARTTLSRefused(t *testing.T) {
	testTable := map[string]struct {
		Reply     string
		Condition string
	}{
		"failure":       {"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>", ""},
		"failure text":  {"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'>\n<text>TLS unavailable</text>\n</failure>", ""},
		"stream error":  {"<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>", "policy-violation"},
		"stream closed": {"</stream:stream>", ""},
		"badsplit":      {"<proceee xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", ""},
		"nonstd":        {"<success xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", ""},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runXMPPPreTLS(serverConn, testHeader+testFeatures, test.Reply, 2, func(net.Conn) {})

			scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
			status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
			if status != zgrab2.SCAN_APPLICATION_ERROR {
				t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
			}
			if result == nil || result.(*ScanResults).StartTLS != test.Reply || result.(*ScanResults).StreamError != test.Condition {
				t.Errorf("expected STARTTLS response %q and stream error %q in result, got %v", test.Reply, test.Condition, result)
			}
		})
	}
}

func TestXMPPSTARTTLSOverride(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runXMPPPreTLS(serverConn, testHeader+"<stream:features/>", testProceed, 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{SendSTARTTLSOverride: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil || result.(*ScanResults).StartTLS != testProceed {
		t.Errorf("expected STARTTLS to be sent despite missing feature, got %v", result)
	}
}

func TestXMPPSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runXMPPPreTLS(serverConn, testHeader+testFeatures, testProceed, 1, func(net.Conn) {})

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestXMPPNotXMPP(t *testing.T) {
	for _, reply := range []string{"HTTP/1.1 400 Bad Request\r\n\r\n", "SSH-2.0-OpenSSH_9.6\r\n", "<?xml version='1.0'?><html><body>stream:stream</body></html>"} {
		clientConn, serverConn := net.Pipe()
		runXMPPPreTLS(serverConn, reply, "", 1, nil)

		scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if status != zgrab2.SCAN_PROTOCOL_ERROR {
			t.Errorf("%q: expected SCAN_PROTOCOL_ERROR, got %s", reply, status)
		}
		if result != nil {
			t.Errorf("%q: expected nil result for non-XMPP response, got %v", reply, result)
		}
	}
}

func TestXMPPNoReply(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runXMPPPreTLS(serverConn, "", "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if expected := zgrab2.TryGetScanStatus(io.EOF); status != expected {
		t.Errorf("expected %s, got %s", expected, status)
	}
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

func TestXMPPCutHeader(t *testing.T) {
	reply := "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' from="
	clientConn, serverConn := net.Pipe()
	runXMPPPreTLS(serverConn, reply, "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s", status)
	}
	if result != nil {
		t.Errorf("expected nil result for an incomplete header, got %v", result)
	}
}

func TestXMPPOtherPrefix(t *testing.T) {
	reply := "<?xml version='1.0'?><str:stream xmlns:str='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'><str:features/>"
	clientConn, serverConn := net.Pipe()
	runXMPPPreTLS(serverConn, reply, "", 1, nil)

	scanner, dialGroup, target := newTestScan(&Flags{}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s", status)
	}
	if result == nil || result.(*ScanResults).Banner != reply {
		t.Errorf("expected banner in result, got %v", result)
	}
}

func TestXMPPSecure(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()
	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(conn *stdtls.Conn) {
		buf := make([]byte, 512)
		conn.Read(buf) // opening stream header
		// Even if listed over TLS, which XEP-0368 forbids, STARTTLS must not be sent.
		conn.Write([]byte(testHeader + testFeatures))
	})

	scanner, dialGroup, target := newTestScan(&Flags{XMPPSecure: true}, clientConn, testhelpers.MakeInsecureTLSWrapper())
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if srvErr := <-srvDone; srvErr != nil {
		t.Fatalf("server-side TLS error: %v", srvErr)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	xmppResult := result.(*ScanResults)
	if !xmppResult.ImplicitTLS || xmppResult.TLSLog == nil || xmppResult.StartTLS != "" {
		t.Errorf("expected implicit TLS without STARTTLS, got %+v", xmppResult)
	}
	if xmppResult.Banner != testHeader+testFeatures || xmppResult.Features != testFeatures {
		t.Errorf("expected banner and features read over TLS, got %+v", xmppResult)
	}
}

func TestXMPPSecureRefused(t *testing.T) {
	for _, reply := range []string{
		testHeader + "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>",
		testHeader + "</stream:stream>",
	} {
		cert := testhelpers.GenerateTestCert(t)
		clientConn, serverConn := net.Pipe()
		srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(conn *stdtls.Conn) {
			buf := make([]byte, 512)
			conn.Read(buf) // opening stream header
			conn.Write([]byte(reply))
		})

		scanner, dialGroup, target := newTestScan(&Flags{XMPPSecure: true}, clientConn, testhelpers.MakeInsecureTLSWrapper())
		status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
		if srvErr := <-srvDone; srvErr != nil {
			t.Fatalf("server-side TLS error: %v", srvErr)
		}
		if status != zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
			t.Errorf("%q: expected SCAN_POST_TLS_APPLICATION_ERROR, got %s", reply, status)
		}
		if result == nil || result.(*ScanResults).TLSLog == nil || result.(*ScanResults).Banner != reply {
			t.Errorf("%q: expected banner and TLS log in result, got %v", reply, result)
		}
	}
}

func TestXMPPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner, dialGroup, target := newTestScan(&Flags{XMPPSecure: true}, clientConn, testhelpers.MakeFailingTLSWrapper())
	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestValidate(t *testing.T) {
	if err := (Flags{XMPPSecure: true, SendSTARTTLSOverride: true}).Validate(nil); err == nil {
		t.Error("expected error for --xmpps with --send-starttls-override")
	}
	if err := (Flags{XMPPSecure: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
