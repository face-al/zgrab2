// Package sslv2 provides a zgrab2 module that scans for SSL 2.0 servers.
// Default Port: 443 (TCP)
//
// The scanner sends an SSL 2.0 CLIENT-HELLO (draft-hickman-netscape-ssl-00,
// section 5.5.1) in a record with a 2-byte header (section 4.1): version
// 0x0002, all seven cipher kinds of Appendix C.4, no session identifier and
// a random 16-byte challenge. These are the bytes of TLS-Attacker's SSL2
// ClientHello. The scanner then reads one record and its message.
//
// A SERVER-HELLO (section 5.6.1) that answers a CLIENT-HELLO without a
// session identifier is a success: SESSION-ID-HIT 0, certificate type
// SSL_CT_X509_CERTIFICATE, version 0x0002, a certificate, one or more cipher
// specs, a connection identifier of 16 to 32 bytes, and lengths that add up
// to the record length. The certificate is also parsed as X.509; a parse
// failure is kept in the results and does not fail the scan.
//
// An ERROR message (section 5.7.1) with a known error code is an
// application error: the server speaks SSL 2.0 but refused the CLIENT-HELLO.
// A TLS record (e.g. the alert OpenSSL 1.1 and later send), any other
// message or record, or a record cut short is a protocol error. A connection
// closed without a reply, as SSL 3.0 and TLS servers without SSL 2.0 support
// usually do, is reported as connection-closed.
//
// The scanner stops after the SERVER-HELLO: it does not send a
// CLIENT-MASTER-KEY, so no keys are exchanged and the server's
// SERVER-VERIFY is not checked. TLS-Attacker's SSL2 hello likewise ends
// with the SERVER-HELLO.
//
// The output contains the SERVER-HELLO or the ERROR, the length of the
// record header, and the bytes read (up to 4096).
package sslv2

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// ServerHello is the server's SERVER-HELLO.
	ServerHello *ServerHello `json:"server_hello,omitempty"`

	// Error is the server's ERROR message.
	Error *ErrorMessage `json:"error,omitempty"`

	// HeaderLength is the length of the reply's record header, 2 or 3.
	HeaderLength int `json:"header_len,omitempty"`

	// Raw is the hex encoding of the bytes read from the server, up to 4096.
	Raw string `json:"raw,omitempty"`
}

// Flags holds the command-line configuration for the SSL 2.0 scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("sslv2", "SSL 2.0",
		"Send an SSL 2.0 CLIENT-HELLO and read the server's SERVER-HELLO.", 443)
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags Flags) Validate(_ []string) error {
	return nil
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// Scan performs the SSL 2.0 scan.
//  1. Open a TCP connection to the target port (default 443).
//  2. Send a CLIENT-HELLO.
//  3. Read one record and check its SERVER-HELLO or ERROR.
//  4. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. SSL 2.0 requires a L4 dialer")
	}
	challenge, err := newChallenge()
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, fmt.Errorf("could not generate challenge: %w", err)
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	if _, err = conn.Write(clientHello(challenge)); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send CLIENT-HELLO: %w", err)
	}
	sslConn := Connection{Conn: conn}
	msg, headerLength, err := sslConn.ReadMessage()
	result := &ScanResults{HeaderLength: headerLength}
	if raw := sslConn.Raw(); len(raw) > 0 {
		result.Raw = hex.EncodeToString(raw)
	}
	if err != nil {
		if result.Raw == "" {
			result = nil
		}
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read reply to CLIENT-HELLO from %s: %w", target.String(), err)
	}

	if msg[0] == msgError {
		result.Error, err = ParseError(msg)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("SSL 2.0 ERROR %s (0x%04x) returned from CLIENT-HELLO", result.Error.Name, result.Error.Code)
	}
	result.ServerHello, err = ParseServerHello(msg)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}
