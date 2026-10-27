package nbd

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// newstyleGreeting is NBDMAGIC, IHAVEOPT and the given handshake flags.
func newstyleGreeting(flags uint16) []byte {
	b := binary.BigEndian.AppendUint64(nil, nbdMagic)
	b = binary.BigEndian.AppendUint64(b, optMagic)
	return binary.BigEndian.AppendUint16(b, flags)
}

// oldstyleGreeting is a whole oldstyle greeting: NBDMAGIC, cliserv_magic,
// export size, flags and 124 bytes of zeroes.
var oldstyleGreeting = func() []byte {
	b := binary.BigEndian.AppendUint64(nil, nbdMagic)
	b = binary.BigEndian.AppendUint64(b, cliservMagic)
	b = binary.BigEndian.AppendUint64(b, 1<<20)
	b = binary.BigEndian.AppendUint32(b, 1)
	return append(b, make([]byte, 124)...)
}()

// optionReply encodes an option reply with the given magic, option, type and data.
func optionReplyWithMagic(magic uint64, option, replyType uint32, data string) []byte {
	b := binary.BigEndian.AppendUint64(nil, magic)
	b = binary.BigEndian.AppendUint32(b, option)
	b = binary.BigEndian.AppendUint32(b, replyType)
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

func optionReply(option, replyType uint32, data string) []byte {
	return optionReplyWithMagic(replyMagic, option, replyType, data)
}

var ack = optionReply(optStartTLS, repAck, "")

// writePieces writes b to conn in the given number of pieces.
func writePieces(conn net.Conn, b []byte, pieces int) {
	size := (len(b) + pieces - 1) / pieces
	for len(b) > 0 {
		n := min(size, len(b))
		conn.Write(b[:n])
		b = b[n:]
	}
}

// runNBDPreTLS runs a fake NBD server on serverConn: it greets, and if reply
// is not nil, checks the client flags and NBD_OPT_STARTTLS, writes reply and
// calls fn. The returned channel receives the server's error, nil if none.
func runNBDPreTLS(serverConn net.Conn, greeting, reply []byte, pieces int, fn func(net.Conn) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		writePieces(serverConn, greeting, pieces)
		if reply == nil {
			done <- nil
			return
		}
		buf := make([]byte, len(startTLSRequest()))
		if _, err := io.ReadFull(serverConn, buf); err != nil || !bytes.Equal(buf, startTLSRequest()) {
			done <- fmt.Errorf("unexpected NBD_OPT_STARTTLS request %x (%v)", buf, err)
			return
		}
		writePieces(serverConn, reply, pieces)
		if fn != nil {
			done <- fn(serverConn)
			return
		}
		done <- nil
	}()
	return done
}

// checkServer fails the test if the fake server reported an error.
func checkServer(t *testing.T, done <-chan error) {
	t.Helper()
	if err := <-done; err != nil {
		t.Errorf("server: %v", err)
	}
}

// answerAbort reads NBD_OPT_ABORT from conn and writes reply, if any.
func answerAbort(conn net.Conn, reply []byte) error {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, optionRequest(optAbort)) {
		return fmt.Errorf("unexpected NBD_OPT_ABORT request %x (%v)", buf, err)
	}
	if reply != nil {
		conn.Write(reply)
	}
	return nil
}

func scanNBD(clientConn net.Conn, flags *Flags, tlsWrapper func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error)) (zgrab2.ScanStatus, *ScanResults, error) {
	scanner := &Scanner{config: flags}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 10809}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: tlsWrapper,
	}
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	nbdResult, _ := result.(*ScanResults)
	return status, nbdResult, err
}

// TestStartTLSRequestBytes checks the request against TLS-Attacker's
// NbdWording.STARTTLS_OPTION.
func TestStartTLSRequestBytes(t *testing.T) {
	expected := "00000001" + "49484156454f5054" + "00000005" + "00000000"
	if got := hex.EncodeToString(startTLSRequest()); got != expected {
		t.Errorf("startTLSRequest() = %s, wanted %s", got, expected)
	}
	if got := hex.EncodeToString(optionRequest(optAbort)); got != "49484156454f5054"+"00000002"+"00000000" {
		t.Errorf("optionRequest(optAbort) = %s", got)
	}
}

func TestNBDSTARTTLSSuccess(t *testing.T) {
	for _, flags := range []uint16{flagFixedNewstyle | flagNoZeroes, flagFixedNewstyle} {
		cert := testhelpers.GenerateTestCert(t)
		clientConn, serverConn := net.Pipe()

		srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flags), ack, 7, func(conn net.Conn) error {
			return stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}}).Handshake()
		})

		status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeInsecureTLSWrapper())
		checkServer(t, srvDone)
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("flags 0x%04x: expected SCAN_SUCCESS, got %s", flags, status)
		}
		if result.Greeting != hex.EncodeToString(newstyleGreeting(flags)) || result.Negotiation != negotiationFixedNewstyle ||
			result.HandshakeFlags == nil || *result.HandshakeFlags != flags {
			t.Errorf("flags 0x%04x: unexpected greeting %+v", flags, result)
		}
		if result.StartTLS == nil || result.StartTLS.ReplyType != repAck || result.StartTLS.ReplyName != "NBD_REP_ACK" ||
			result.StartTLS.Option != optStartTLS || result.StartTLS.Raw != hex.EncodeToString(ack) {
			t.Errorf("expected NBD_REP_ACK, got %+v", result.StartTLS)
		}
		if result.Abort != nil {
			t.Errorf("expected no NBD_OPT_ABORT without --send-abort, got %+v", result.Abort)
		}
		if result.TLSLog == nil || result.TLSLog.HandshakeLog == nil {
			t.Fatal("expected TLS log")
		}
	}
}

func TestNBDSendAbortOverTLS(t *testing.T) {
	testTable := map[string]struct {
		Reply  []byte
		Status zgrab2.ScanStatus
	}{
		"ack":       {optionReply(optAbort, repAck, ""), zgrab2.SCAN_SUCCESS},
		"no reply":  {nil, zgrab2.SCAN_SUCCESS},
		"error":     {optionReply(optAbort, repError+3, ""), zgrab2.SCAN_POST_TLS_APPLICATION_ERROR},
		"truncated": {optionReply(optAbort, repAck, "")[:10], zgrab2.SCAN_POST_TLS_APPLICATION_ERROR},
	}
	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			cert := testhelpers.GenerateTestCert(t)
			clientConn, serverConn := net.Pipe()
			srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|flagNoZeroes), ack, 1, func(conn net.Conn) error {
				srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
				defer srv.Close()
				if err := srv.Handshake(); err != nil {
					return err
				}
				return answerAbort(srv, test.Reply)
			})

			status, result, _ := scanNBD(clientConn, &Flags{SendAbort: true}, testhelpers.MakeInsecureTLSWrapper())
			checkServer(t, srvDone)
			if status != test.Status {
				t.Fatalf("expected %s, got %s", test.Status, status)
			}
			if result.TLSLog == nil {
				t.Error("expected TLS log")
			}
			if test.Reply == nil && result.Abort != nil {
				t.Errorf("expected no NBD_OPT_ABORT reply, got %+v", result.Abort)
			}
			if test.Reply != nil && (result.Abort == nil || result.Abort.Raw != hex.EncodeToString(test.Reply)) {
				t.Errorf("expected NBD_OPT_ABORT reply %x, got %+v", test.Reply, result.Abort)
			}
		})
	}
}

func TestNBDSTARTTLSRefused(t *testing.T) {
	testTable := map[string]struct {
		ReplyType uint32
		Data      string
		Name      string
		Message   string
	}{
		"policy":        {repError + 2, "TLS not allowed on this server", "NBD_REP_ERR_POLICY", "TLS not allowed on this server"},
		"unsupported":   {repError + 1, "", "NBD_REP_ERR_UNSUP", ""},
		"invalid":       {repError + 3, "TLS already negotiated", "NBD_REP_ERR_INVALID", "TLS already negotiated"},
		"tls reqd":      {repError + 5, "", "NBD_REP_ERR_TLS_REQD", ""},
		"unknown error": {repError + 99, "x", "", "x"},
		"server":        {2, "", "NBD_REP_SERVER", ""},
		"type zero":     {0, "", "", ""},
		"long message":  {repError + 2, strings.Repeat("m", 5000), "NBD_REP_ERR_POLICY", strings.Repeat("m", maxReplyData)},
	}
	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			reply := optionReply(optStartTLS, test.ReplyType, test.Data)
			clientConn, serverConn := net.Pipe()
			srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|flagNoZeroes), reply, 3, nil)

			status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
			checkServer(t, srvDone)
			if status != zgrab2.SCAN_APPLICATION_ERROR {
				t.Fatalf("expected SCAN_APPLICATION_ERROR, got %s", status)
			}
			if result.StartTLS == nil || result.StartTLS.ReplyType != test.ReplyType || result.StartTLS.ReplyName != test.Name ||
				result.StartTLS.Message != test.Message || result.StartTLS.Raw != hex.EncodeToString(reply[:min(len(reply), replyHeaderSize+maxReplyData)]) {
				t.Errorf("unexpected reply %+v", result.StartTLS)
			}
			if result.StartTLS.length != uint32(len(test.Data)) {
				t.Errorf("expected data length %d, got %d", len(test.Data), result.StartTLS.length)
			}
			if result.TLSLog != nil || result.Abort != nil {
				t.Errorf("expected no TLS log or abort, got %+v", result)
			}
		})
	}
}

func TestNBDSendAbortAfterRefusal(t *testing.T) {
	abortAck := optionReply(optAbort, repAck, "")
	clientConn, serverConn := net.Pipe()
	srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|flagNoZeroes), optionReply(optStartTLS, repError+2, ""), 1,
		func(conn net.Conn) error { return answerAbort(conn, abortAck) })

	status, result, _ := scanNBD(clientConn, &Flags{SendAbort: true}, testhelpers.MakeFailingTLSWrapper())
	checkServer(t, srvDone)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Fatalf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if result.Abort == nil || result.Abort.ReplyType != repAck || result.Abort.Option != optAbort {
		t.Errorf("expected NBD_REP_ACK to NBD_OPT_ABORT, got %+v", result.Abort)
	}
}

// TestNBDNoAbortAfterTruncatedRefusal checks that NBD_OPT_ABORT is not sent
// after a reply whose data was not read to its end.
func TestNBDNoAbortAfterTruncatedRefusal(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|flagNoZeroes),
		optionReply(optStartTLS, repError+2, strings.Repeat("m", maxReplyData+1)), 1, nil)

	status, result, _ := scanNBD(clientConn, &Flags{SendAbort: true}, testhelpers.MakeFailingTLSWrapper())
	checkServer(t, srvDone)
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Fatalf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	if result.Abort != nil {
		t.Errorf("expected no NBD_OPT_ABORT, got %+v", result.Abort)
	}
}

func TestNBDSTARTTLSMalformedReply(t *testing.T) {
	testTable := map[string][]byte{
		"ack for other option": optionReply(optAbort, repAck, ""),
		"ack with data":        optionReply(optStartTLS, repAck, "x"),
		"wrong magic":          optionReplyWithMagic(nbdMagic, optStartTLS, repAck, ""),
		"truncated header":     ack[:15],
		"truncated data":       optionReply(optStartTLS, repError+2, "TLS not allowed")[:25],
		"header only":          optionReply(optStartTLS, repError+2, "TLS not allowed")[:replyHeaderSize],
	}
	for name, reply := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|flagNoZeroes), reply, 2, nil)

			status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
			checkServer(t, srvDone)
			if status != zgrab2.SCAN_PROTOCOL_ERROR {
				t.Fatalf("expected SCAN_PROTOCOL_ERROR, got %s", status)
			}
			if result.StartTLS == nil || result.StartTLS.Raw != hex.EncodeToString(reply) {
				t.Errorf("expected raw reply %x, got %+v", reply, result.StartTLS)
			}
			if result.TLSLog != nil {
				t.Error("expected no TLS log")
			}
		})
	}
}

// TestNBDHandshakeError checks that bytes after the ACK, or a failed handshake,
// are a handshake error with the reply kept.
func TestNBDHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|flagNoZeroes), ack, 1, nil)

	status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
	checkServer(t, srvDone)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Fatalf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result.StartTLS == nil || result.StartTLS.ReplyType != repAck {
		t.Errorf("expected NBD_REP_ACK, got %+v", result.StartTLS)
	}
}

// TestNBDConnectionClosed checks a server that closes after its greeting.
func TestNBDConnectionClosed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		serverConn.Write(newstyleGreeting(flagFixedNewstyle | flagNoZeroes))
		io.ReadFull(serverConn, make([]byte, len(startTLSRequest())))
		serverConn.Close()
	}()

	status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
	// io.EOF before the first byte of the reply maps to SCAN_IO_TIMEOUT.
	if status != zgrab2.SCAN_IO_TIMEOUT {
		t.Fatalf("expected SCAN_IO_TIMEOUT, got %s", status)
	}
	if result == nil || result.Negotiation != negotiationFixedNewstyle || result.StartTLS != nil {
		t.Errorf("expected greeting and no reply, got %+v", result)
	}
}

func TestNBDWithoutTLS(t *testing.T) {
	testTable := map[string]struct {
		Greeting    []byte
		Negotiation string
	}{
		"oldstyle":        {oldstyleGreeting, negotiationOldstyle},
		"newstyle":        {newstyleGreeting(0), negotiationNewstyle},
		"newstyle zeroes": {newstyleGreeting(flagNoZeroes), negotiationNewstyle},
	}
	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			srvDone := runNBDPreTLS(serverConn, test.Greeting, nil, 1, nil)

			status, result, _ := scanNBD(clientConn, &Flags{SendAbort: true}, testhelpers.MakeFailingTLSWrapper())
			checkServer(t, srvDone)
			if status != zgrab2.SCAN_SUCCESS {
				t.Fatalf("expected SCAN_SUCCESS, got %s", status)
			}
			if result.Negotiation != test.Negotiation || result.StartTLS != nil || result.Abort != nil {
				t.Errorf("unexpected result %+v", result)
			}
			if test.Negotiation == negotiationOldstyle && (result.HandshakeFlags != nil || result.Greeting != hex.EncodeToString(test.Greeting[:greetingMagicsSize])) {
				t.Errorf("unexpected oldstyle greeting %+v", result)
			}
		})
	}
}

func TestNBDUnknownHandshakeFlags(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	srvDone := runNBDPreTLS(serverConn, newstyleGreeting(flagFixedNewstyle|1<<2), nil, 1, nil)

	status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
	checkServer(t, srvDone)
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Fatalf("expected SCAN_PROTOCOL_ERROR, got %s", status)
	}
	if result == nil || result.HandshakeFlags == nil || *result.HandshakeFlags != 0x0005 || result.StartTLS != nil {
		t.Errorf("expected greeting kept and no NBD_OPT_STARTTLS, got %+v", result)
	}
}

func TestNBDNotNBD(t *testing.T) {
	testTable := map[string]struct {
		Greeting []byte
		// Kept is the number of bytes of the greeting the result keeps: all
		// those read once both magics are, NBDMAGIC first.
		Kept int
	}{
		"smtp banner":      {[]byte("220 mail.example.com ESMTP Postfix\r\n"), 0},
		"truncated magics": {newstyleGreeting(flagFixedNewstyle)[:12], 0},
		"wrong magic":      {append(binary.BigEndian.AppendUint64(nil, nbdMagic), "IHAVEOPS\x00\x03"...), 16},
		"truncated flags":  {newstyleGreeting(flagFixedNewstyle)[:17], 17},
	}
	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			srvDone := runNBDPreTLS(serverConn, test.Greeting, nil, 1, nil)

			status, result, _ := scanNBD(clientConn, &Flags{}, testhelpers.MakeFailingTLSWrapper())
			checkServer(t, srvDone)
			if status != zgrab2.SCAN_PROTOCOL_ERROR {
				t.Fatalf("expected SCAN_PROTOCOL_ERROR, got %s", status)
			}
			if test.Kept == 0 && result != nil {
				t.Errorf("expected no result, got %+v", result)
			}
			if test.Kept > 0 && (result == nil || result.Greeting != hex.EncodeToString(test.Greeting[:test.Kept]) || result.Negotiation != "") {
				t.Errorf("expected only the greeting kept, got %+v", result)
			}
		})
	}
}
