package ldap

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// tlv84 encodes a BER element with a four-octet long-form length, as Active
// Directory does for every element.
func tlv84(tag byte, content []byte) []byte {
	n := len(content)
	return append([]byte{tag, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, content...)
}

func ldapResultContent(code int, diagnosticMessage string) []byte {
	var b []byte
	b = append(b, tlv(tagEnumerated, berInt(code))...)
	b = append(b, tlv(tagOctetString, nil)...)
	return append(b, tlv(tagOctetString, []byte(diagnosticMessage))...)
}

func rootDSEEntry(msgID int, extensions ...string) []byte {
	values := make([]byte, 0, 32*len(extensions))
	for _, extension := range extensions {
		values = append(values, tlv(tagOctetString, []byte(extension))...)
	}
	attributes := tlv(tagSequence, append(tlv(tagOctetString, []byte("supportedLDAPVersion")), tlv(tagSet, tlv(tagOctetString, []byte("3")))...))
	if len(extensions) > 0 {
		attributes = append(attributes, tlv(tagSequence, append(tlv(tagOctetString, []byte("supportedExtension")), tlv(tagSet, values)...))...)
	}
	entry := append(tlv(tagOctetString, nil), tlv(tagSequence, attributes)...)
	return envelope(msgID, tlv(tagSearchResultEntry, entry))
}

func searchResultDone(msgID, code int) []byte {
	return envelope(msgID, tlv(tagSearchResultDone, ldapResultContent(code, "")))
}

func extendedResponseMessage(msgID, code int, responseName string) []byte {
	content := ldapResultContent(code, "")
	if responseName != "" {
		content = append(content, tlv(tagExtendedResponseName, []byte(responseName))...)
	}
	return envelope(msgID, tlv(tagExtendedResponse, content))
}

// adRootDSE is a root DSE reply in Active Directory's encoding: four-octet
// lengths on constructed elements, and a control after the SearchResultDone's
// LDAPResult.
var adRootDSE = func() []byte {
	attribute := tlv84(tagSequence, append(tlv84(tagOctetString, []byte("supportedExtension")),
		tlv84(tagSet, append(tlv84(tagOctetString, []byte("1.2.840.113556.1.4.1781")), tlv84(tagOctetString, []byte(startTLSOID))...))...))
	entry := append(tlv84(tagOctetString, nil), tlv84(tagSequence, attribute)...)
	id := tlv(tagInteger, berInt(1))
	done := append(tlv84(tagSearchResultDone, ldapResultContent(0, "")), tlv(0xa0, nil)...)
	return append(tlv84(tagSequence, append(id, tlv84(tagSearchResultEntry, entry)...)),
		tlv84(tagSequence, append(id, done...))...)
}()

var noticeOfDisconnection = extendedResponseMessage(0, 52, noticeOfDisconnectionOID)

func TestNextTLV(t *testing.T) {
	testTable := map[string]struct {
		Input   []byte
		Content []byte
		OK      bool
	}{
		"short form":         {[]byte{0x04, 0x02, 'h', 'i', 0xff}, []byte("hi"), true},
		"long form":          {[]byte{0x04, 0x81, 0x02, 'h', 'i'}, []byte("hi"), true},
		"four-octet length":  {tlv84(tagOctetString, []byte("hi")), []byte("hi"), true},
		"empty":              {[]byte{0x04, 0x00}, []byte{}, true},
		"truncated content":  {[]byte{0x04, 0x05, 'h', 'i'}, nil, false},
		"truncated length":   {[]byte{0x04, 0x82, 0x01}, nil, false},
		"indefinite length":  {[]byte{0x30, 0x80, 0x00, 0x00}, nil, false},
		"five-octet length":  {[]byte{0x04, 0x85, 0, 0, 0, 0, 2, 'h', 'i'}, nil, false},
		"high tag number":    {[]byte{0x1f, 0x01, 0x00}, nil, false},
		"single byte":        {[]byte{0x04}, nil, false},
		"length overflowing": {[]byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, nil, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			_, content, _, err := nextTLV(test.Input)
			if (err == nil) != test.OK {
				t.Fatalf("nextTLV(%x) error = %v, wanted ok=%v", test.Input, err, test.OK)
			}
			if test.OK && !bytes.Equal(content, test.Content) {
				t.Errorf("nextTLV(%x) content = %x, wanted %x", test.Input, content, test.Content)
			}
		})
	}
}

func TestParseInt(t *testing.T) {
	testTable := map[string]struct {
		Input    []byte
		Expected int
		OK       bool
	}{
		"zero":            {[]byte{0x00}, 0, true},
		"one":             {[]byte{0x01}, 1, true},
		"high bit":        {[]byte{0x00, 0x80}, 128, true},
		"negative":        {[]byte{0xff}, -1, true},
		"negative 128":    {[]byte{0x80}, -128, true},
		"max int32":       {[]byte{0x7f, 0xff, 0xff, 0xff}, 1<<31 - 1, true},
		"padded":          {[]byte{0x00, 0x00, 0x00, 0x01}, 0, false},
		"padded zero":     {[]byte{0x00, 0x00}, 0, false},
		"padded negative": {[]byte{0xff, 0xff}, 0, false},
		"too long":        {[]byte{0x01, 0x00, 0x00, 0x00, 0x00}, 0, false},
		"padded too long": {[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 0, false},
		"empty":           {[]byte{}, 0, false},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			got, err := parseInt(test.Input)
			if (err == nil) != test.OK {
				t.Fatalf("parseInt(%x) error = %v, wanted ok=%v", test.Input, err, test.OK)
			}
			if test.OK && got != test.Expected {
				t.Errorf("parseInt(%x) = %d, wanted %d", test.Input, got, test.Expected)
			}
		})
	}
}

func TestReadRootDSE(t *testing.T) {
	testTable := map[string]struct {
		Reply      []byte
		Advertised bool
		ResultCode int
		OK         bool
	}{
		"starttls advertised":     {append(rootDSEEntry(1, "1.3.6.1.4.1.4203.1.11.1", startTLSOID), searchResultDone(1, 0)...), true, 0, true},
		"starttls not advertised": {append(rootDSEEntry(1, "1.3.6.1.4.1.4203.1.11.1"), searchResultDone(1, 0)...), false, 0, true},
		"no extensions":           {append(rootDSEEntry(1), searchResultDone(1, 0)...), false, 0, true},
		"active directory":        {adRootDSE, true, 0, true},
		"padded message id":       {tlv(tagSequence, append(tlv(tagInteger, []byte{0x00, 0x01}), tlv(tagSearchResultDone, ldapResultContent(0, ""))...)), false, 0, false},
		"access denied":           {searchResultDone(1, 50), false, 50, true},
		"reference skipped": {append(append(rootDSEEntry(1, startTLSOID),
			envelope(1, tlv(tagSearchResultReference, tlv(tagOctetString, []byte("ldap://other/"))))...), searchResultDone(1, 0)...), true, 0, true},
		"wrong message id":        {append(rootDSEEntry(5, startTLSOID), searchResultDone(5, 0)...), false, 0, false},
		"bind response":           {envelope(1, tlv(0x61, ldapResultContent(0, ""))), false, 0, false},
		"truncated":               {rootDSEEntry(1, startTLSOID)[:10], false, 0, false},
		"entry without done":      {rootDSEEntry(1, startTLSOID), false, 0, false},
		"oid as substring is not": {append(rootDSEEntry(1, startTLSOID+".1"), searchResultDone(1, 0)...), false, 0, true},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			go func() {
				serverConn.Write(test.Reply)
				serverConn.Close()
			}()
			rootDSE, _, err := readRootDSE(&Connection{Conn: clientConn})
			if (err == nil) != test.OK {
				t.Fatalf("readRootDSE error = %v, wanted ok=%v", err, test.OK)
			}
			if !test.OK {
				return
			}
			if got := supportsSTARTTLS(rootDSE); got != test.Advertised {
				t.Errorf("supportsSTARTTLS = %v, wanted %v", got, test.Advertised)
			}
			if rootDSE.ResultCode == nil || *rootDSE.ResultCode != test.ResultCode {
				t.Errorf("result code = %v, wanted %d", rootDSE.ResultCode, test.ResultCode)
			}
		})
	}
}

// runLDAPPreTLS answers the root DSE search with rootDSE and, if startTLS is
// non-nil, the StartTLS request with startTLS, then calls fn with serverConn
// so the caller can handle the TLS phase. Each reply is written in the given
// number of pieces to exercise reassembly. Runs in a goroutine; closes
// serverConn when done.
func runLDAPPreTLS(t *testing.T, serverConn net.Conn, rootDSE, startTLS []byte, pieces int, fn func(net.Conn)) {
	write := func(b []byte) {
		size := (len(b) + pieces - 1) / pieces
		for len(b) > 0 {
			n := min(size, len(b))
			serverConn.Write(b[:n])
			b = b[n:]
		}
	}
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		n, _ := serverConn.Read(buf) // root DSE search
		if !bytes.Equal(buf[:n], rootDSERequest(rootDSEMessageID)) {
			t.Errorf("unexpected root DSE request %x", buf[:n])
		}
		write(rootDSE)
		if startTLS == nil {
			return
		}
		n, _ = serverConn.Read(buf) // StartTLS
		if !bytes.Equal(buf[:n], startTLSRequest(startTLSMessageID)) {
			t.Errorf("unexpected StartTLS request %x", buf[:n])
		}
		write(startTLS)
		fn(serverConn)
	}()
}

func scanLDAP(clientConn net.Conn, flags *Flags, tlsWrapper func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error)) (zgrab2.ScanStatus, *ScanResults, error) {
	scanner := &Scanner{config: flags}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 389}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: tlsWrapper,
	}
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	ldapResult, _ := result.(*ScanResults)
	return status, ldapResult, err
}

func TestLDAPSTARTTLSSuccess(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := make(chan error, 1)
	runLDAPPreTLS(t, serverConn, adRootDSE, extendedResponseMessage(2, 0, startTLSOID), 7,
		func(conn net.Conn) {
			srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
			srvDone <- srv.Handshake()
		})

	status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeInsecureTLSWrapper())
	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS handshake error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s", status)
	}
	if !supportsSTARTTLS(result.RootDSE) {
		t.Errorf("expected StartTLS in root DSE, got %+v", result.RootDSE)
	}
	if result.RootDSE.Raw != hex.EncodeToString(adRootDSE) {
		t.Errorf("expected raw root DSE reply, got %q", result.RootDSE.Raw)
	}
	if result.StartTLS == nil || result.StartTLS.ResultCode == nil || *result.StartTLS.ResultCode != 0 || result.StartTLS.ResponseName != startTLSOID {
		t.Errorf("expected successful StartTLS response, got %+v", result.StartTLS)
	}
	if result.TLSLog == nil || result.TLSLog.HandshakeLog == nil {
		t.Fatal("expected TLS log")
	}
}

func TestLDAPSTARTTLSNotAdvertised(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLDAPPreTLS(t, serverConn, append(rootDSEEntry(1), searchResultDone(1, 0)...), nil, 1, nil)

	status, result, err := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if result.StartTLS != nil || result.TLSLog != nil {
		t.Errorf("expected no StartTLS attempt, got starttls=%+v tls=%v", result.StartTLS, result.TLSLog)
	}
}

func TestLDAPRootDSEDenied(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLDAPPreTLS(t, serverConn, searchResultDone(1, 50), nil, 1, nil)

	status, result, err := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if result.RootDSE.ResultName != "insufficientAccessRights" || result.StartTLS != nil {
		t.Errorf("expected denied root DSE and no StartTLS, got %+v", result)
	}
}

func TestLDAPSTARTTLSRefused(t *testing.T) {
	testTable := map[string]struct {
		Code         int
		ResponseName string
	}{
		"protocolError":        {2, startTLSOID},
		"operationsError":      {1, startTLSOID},
		"unwillingToPerform":   {53, ""},
		"unavailable, no name": {52, ""},
		"other":                {80, startTLSOID},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runLDAPPreTLS(t, serverConn, append(rootDSEEntry(1, startTLSOID), searchResultDone(1, 0)...),
				extendedResponseMessage(2, test.Code, test.ResponseName), 2, func(net.Conn) {})

			status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
			if status != zgrab2.SCAN_APPLICATION_ERROR {
				t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
			}
			if result == nil || result.StartTLS == nil || result.StartTLS.ResultCode == nil || *result.StartTLS.ResultCode != test.Code {
				t.Errorf("expected StartTLS response with code %d in result, got %+v", test.Code, result)
			}
		})
	}
}

func TestLDAPSTARTTLSOverride(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLDAPPreTLS(t, serverConn, searchResultDone(1, 50), extendedResponseMessage(2, 0, startTLSOID), 1, func(net.Conn) {})

	status, result, _ := scanLDAP(clientConn, &Flags{SendSTARTTLSOverride: true}, testhelpers.MakeFailingTLSWrapper())
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil || result.StartTLS == nil {
		t.Errorf("expected StartTLS to be sent despite it not being advertised, got %+v", result)
	}
}

func TestLDAPSTARTTLSMalformedResponse(t *testing.T) {
	testTable := map[string][]byte{
		"text":              []byte("hello\r\n"),
		"wrong message id":  extendedResponseMessage(3, 0, startTLSOID),
		"wrong protocolOp":  envelope(2, tlv(0x61, ldapResultContent(0, ""))),
		"truncated result":  envelope(2, tlv(tagExtendedResponse, tlv(tagEnumerated, berInt(0)))),
		"indefinite length": {0x30, 0x80, 0x02, 0x01, 0x02},
		"padded resultCode": envelope(2, tlv(tagExtendedResponse, append(tlv(tagEnumerated, []byte{0x00, 0x00}),
			append(tlv(tagOctetString, nil), tlv(tagOctetString, nil)...)...))),
	}

	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runLDAPPreTLS(t, serverConn, append(rootDSEEntry(1, startTLSOID), searchResultDone(1, 0)...), reply, 1, func(net.Conn) {})

			status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
			if status != zgrab2.SCAN_PROTOCOL_ERROR {
				t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s", status)
			}
			if result == nil || result.RootDSE == nil || result.StartTLS == nil || result.StartTLS.Raw == "" {
				t.Errorf("expected root DSE and raw StartTLS reply kept, got %+v", result)
			}
			if result != nil && result.TLSLog != nil {
				t.Errorf("expected no TLS handshake, got %+v", result.TLSLog)
			}
		})
	}
}

func TestLDAPNoticeOfDisconnection(t *testing.T) {
	t.Run("instead of root DSE", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		runLDAPPreTLS(t, serverConn, noticeOfDisconnection, nil, 1, nil)

		status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
		if status != zgrab2.SCAN_APPLICATION_ERROR {
			t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
		}
		if result == nil || result.NoticeOfDisconnection == nil || result.NoticeOfDisconnection.ResultName != "unavailable" {
			t.Errorf("expected Notice of Disconnection in result, got %+v", result)
		}
	})
	t.Run("instead of StartTLS response", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		runLDAPPreTLS(t, serverConn, append(rootDSEEntry(1, startTLSOID), searchResultDone(1, 0)...), noticeOfDisconnection, 1, func(net.Conn) {})

		status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
		if status != zgrab2.SCAN_APPLICATION_ERROR {
			t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
		}
		if result == nil || result.NoticeOfDisconnection == nil || result.StartTLS != nil {
			t.Errorf("expected Notice of Disconnection and no StartTLS response in result, got %+v", result)
		}
	})
}

func TestLDAPNotLDAP(t *testing.T) {
	testTable := map[string][]byte{
		"smtp banner": []byte("220 mail.example.com ESMTP\r\n"),
		"http":        []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"),
		"tls alert":   {0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46},
	}

	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			runLDAPPreTLS(t, serverConn, reply, nil, 1, nil)

			status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
			if status != zgrab2.SCAN_PROTOCOL_ERROR {
				t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s", status)
			}
			if result != nil {
				t.Errorf("expected nil result for non-LDAP response, got %+v", result)
			}
		})
	}
}

func TestLDAPConnectionClosed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLDAPPreTLS(t, serverConn, nil, nil, 1, nil)

	status, result, _ := scanLDAP(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
	if status == zgrab2.SCAN_SUCCESS {
		t.Errorf("expected failure status, got %s", status)
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

func TestLDAPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	status, _, _ := scanLDAP(clientConn, &Flags{LDAPSecure: true}, testhelpers.MakeFailingTLSWrapper())
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

func TestLDAPValidate(t *testing.T) {
	if err := (Flags{LDAPSecure: true, SendSTARTTLSOverride: true}).Validate(nil); err == nil {
		t.Error("expected error for --ldaps with --send-starttls-override")
	}
	if err := (Flags{LDAPSecure: true}).Validate(nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestEncoding(t *testing.T) {
	// StartTLS request with messageID 1, captured from OpenLDAP's ldapwhoami -ZZ.
	want, _ := hex.DecodeString("301d02010177188016312e332e362e312e342e312e313436362e3230303337")
	if got := startTLSRequest(1); !bytes.Equal(got, want) {
		t.Errorf("startTLSRequest(1) = %x, wanted %x", got, want)
	}
	_, body, _, err := nextTLV(rootDSERequest(1))
	if err != nil {
		t.Fatalf("rootDSERequest is not a BER element: %v", err)
	}
	msg, err := parseMessage(body)
	if err != nil || msg.ID != 1 || msg.Op != tagSearchRequest {
		t.Fatalf("rootDSERequest does not parse as a SearchRequest: %+v, %v", msg, err)
	}
}

func TestReadMessage(t *testing.T) {
	testTable := map[string]struct {
		Input  []byte
		Status zgrab2.ScanStatus
	}{
		"short length":          {searchResultDone(1, 0), zgrab2.SCAN_SUCCESS},
		"four-octet length":     {tlv84(tagSequence, append(tlv(tagInteger, berInt(1)), tlv(tagSearchResultDone, ldapResultContent(0, ""))...)), zgrab2.SCAN_SUCCESS},
		"five-octet length":     {[]byte{0x30, 0x85, 0, 0, 0, 0, 3, 0x02, 0x01, 0x01}, zgrab2.SCAN_PROTOCOL_ERROR},
		"indefinite length":     {[]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}, zgrab2.SCAN_PROTOCOL_ERROR},
		"length above limit":    {[]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, zgrab2.SCAN_PROTOCOL_ERROR},
		"length overflowing":    {[]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, zgrab2.SCAN_PROTOCOL_ERROR},
		"one byte":              {[]byte{0x30}, zgrab2.SCAN_PROTOCOL_ERROR},
		"truncated length":      {[]byte{0x30, 0x82, 0x01}, zgrab2.SCAN_PROTOCOL_ERROR},
		"truncated body":        {searchResultDone(1, 0)[:8], zgrab2.SCAN_PROTOCOL_ERROR},
		"not a sequence":        {[]byte("220 mail.example.com ESMTP\r\n"), zgrab2.SCAN_PROTOCOL_ERROR},
		"missing protocolOp":    {envelope(1, nil), zgrab2.SCAN_PROTOCOL_ERROR},
		"connection closed":     {nil, zgrab2.SCAN_IO_TIMEOUT},
		"non-integer messageID": {tlv(tagSequence, append(tlv(tagOctetString, []byte{1}), tlv(tagSearchResultDone, nil)...)), zgrab2.SCAN_PROTOCOL_ERROR},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			go func() {
				serverConn.Write(test.Input)
				serverConn.Close()
			}()
			_, raw, err := (&Connection{Conn: clientConn}).ReadMessage()
			if status := zgrab2.TryGetScanStatus(err); status != test.Status {
				t.Errorf("ReadMessage status = %s (%v), wanted %s", status, err, test.Status)
			}
			if !bytes.HasPrefix(test.Input, raw) {
				t.Errorf("ReadMessage raw = %x, not a prefix of %x", raw, test.Input)
			}
		})
	}
}

// runLDAPSServer performs the server side of a TLS handshake on serverConn,
// then answers the root DSE search over TLS with rootDSE.
func runLDAPSServer(serverConn net.Conn, cert stdtls.Certificate, rootDSE []byte) {
	go func() {
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		defer srv.Close()
		if err := srv.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 512)
		srv.Read(buf) // root DSE search
		srv.Write(rootDSE)
	}()
}

func TestLDAPSSuccess(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()
	runLDAPSServer(serverConn, cert, append(rootDSEEntry(1, startTLSOID), searchResultDone(1, 0)...))

	status, result, err := scanLDAP(clientConn, &Flags{LDAPSecure: true}, testhelpers.MakeInsecureTLSWrapper())
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("expected SCAN_SUCCESS, got %s (%v)", status, err)
	}
	if !result.ImplicitTLS || result.TLSLog == nil || result.StartTLS != nil {
		t.Errorf("expected implicit TLS without StartTLS, got %+v", result)
	}
	if result.RootDSE == nil || len(result.RootDSE.Attributes) == 0 {
		t.Errorf("expected root DSE read over TLS, got %+v", result.RootDSE)
	}
}

func TestLDAPSNoticeOfDisconnection(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()
	runLDAPSServer(serverConn, cert, noticeOfDisconnection)

	status, result, _ := scanLDAP(clientConn, &Flags{LDAPSecure: true}, testhelpers.MakeInsecureTLSWrapper())
	if status != zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
		t.Errorf("expected SCAN_POST_TLS_APPLICATION_ERROR, got %s", status)
	}
	if result == nil || result.NoticeOfDisconnection == nil || result.TLSLog == nil {
		t.Errorf("expected Notice of Disconnection and TLS log in result, got %+v", result)
	}
}

// scanSSLv2 runs an --sslv2 scan against a fake LDAP server that accepts
// StartTLS and then hands the connection to fn.
func scanSSLv2(t *testing.T, fn func(net.Conn)) (zgrab2.ScanStatus, *ScanResults) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	runLDAPPreTLS(t, serverConn, adRootDSE, extendedResponseMessage(2, 0, startTLSOID), 1, fn)

	status, result, _ := scanLDAP(clientConn, &Flags{SSLv2: true}, testhelpers.MakeFailingTLSWrapper())
	return status, result
}

func TestSSLv2UpgradeRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	runLDAPPreTLS(t, serverConn, adRootDSE, extendedResponseMessage(2, 2, startTLSOID), 1, func(net.Conn) {})

	status, result, _ := scanLDAP(clientConn, &Flags{SSLv2: true}, testhelpers.MakeFailingTLSWrapper())
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if result == nil || result.SSLv2 != nil {
		t.Errorf("expected result without sslv2, got %+v", result)
	}
}

func TestSSLv2Validate(t *testing.T) {
	if err := (Flags{LDAPSecure: true, SSLv2: true}).Validate(nil); err == nil {
		t.Error("expected error for --ldaps with --sslv2")
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
