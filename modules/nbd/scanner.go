// Package nbd provides a zgrab2 module that scans for NBD servers.
// Default Port: 10809 (TCP)
//
// The scanner reads the server's greeting (NBD protocol, "Newstyle
// negotiation"). TLS requires fixed newstyle negotiation ("TLS support"), so
// if the server sets NBD_FLAG_FIXED_NEWSTYLE, the scanner sends its client
// flags with only NBD_FLAG_C_FIXED_NEWSTYLE set, then NBD_OPT_STARTTLS, and,
// on an NBD_REP_ACK reply without data, negotiates a TLS connection. Servers
// list STARTTLS nowhere: a server without TLS refuses the option, usually with
// NBD_REP_ERR_POLICY or NBD_REP_ERR_UNSUP ("NOTLS mode"), so the option is
// always sent. A reply of any other type is reported as an application error
// with the reply kept. NBD_REP_ERR_TLS_REQD is not a valid reply to
// NBD_OPT_STARTTLS and is reported the same way. A reply with another magic,
// for another option, or an ACK with data is reported as a protocol error.
// The scanner uses the standard TLS flags for the handshake.
//
// An oldstyle greeting, or a newstyle one without NBD_FLAG_FIXED_NEWSTYLE,
// means the server cannot do TLS; the scan succeeds without sending
// NBD_OPT_STARTTLS. Servers MUST NOT set handshake flags other than
// NBD_FLAG_FIXED_NEWSTYLE and NBD_FLAG_NO_ZEROES ("Handshake flags"); a
// greeting with any other is a protocol error and NBD_OPT_STARTTLS is not
// sent, as TLS-Attacker's greeting pattern does not match it either, although
// clients SHOULD ignore flags they do not recognize ("Newstyle negotiation").
//
// The bytes sent and the checks on the replies match TLS-Attacker's NBD
// STARTTLS, with two differences in how a failure is reported. The scanner
// reads exactly the 20-byte reply header (and its data), so bytes a server
// sends after the ACK go to the TLS handshake and fail it rather than
// refusing the upgrade. An ACK with data, which TLS-Attacker treats as a
// refusal, is a protocol error here, as NBD_REP_ACK has no data ("Option reply
// types").
//
// The --send-abort flag tells the scanner to end option haggling with
// NBD_OPT_ABORT, a soft disconnect ("Termination of the session during option
// haggling"), after a refused or successful upgrade, instead of just closing
// the connection. The server may close the connection without replying. A
// failed NBD_OPT_ABORT after the TLS handshake is a post-TLS application
// error, so TLS support is read from the TLS log, not from the status.
//
// The output contains the server's greeting, its reply to NBD_OPT_STARTTLS
// (if sent) and to NBD_OPT_ABORT (if sent), and if STARTTLS was negotiated,
// the standard TLS logs.
package nbd

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

// Negotiation styles, from the greeting ("Oldstyle negotiation", "Newstyle
// negotiation", "Fixed newstyle negotiation").
const (
	negotiationOldstyle      = "oldstyle"
	negotiationNewstyle      = "newstyle"
	negotiationFixedNewstyle = "fixed_newstyle"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Greeting is the hex encoding of the server's greeting: the two magics,
	// then the handshake flags in newstyle negotiation.
	Greeting string `json:"greeting,omitempty"`

	// Negotiation is oldstyle, newstyle or fixed_newstyle.
	Negotiation string `json:"negotiation,omitempty"`

	// HandshakeFlags are the server's handshake flags, absent in oldstyle negotiation.
	HandshakeFlags *uint16 `json:"handshake_flags,omitempty"`

	// StartTLS is the server's reply to NBD_OPT_STARTTLS, if it is sent.
	StartTLS *OptionReply `json:"starttls,omitempty"`

	// Abort is the server's reply to NBD_OPT_ABORT, if it is sent and answered.
	Abort *OptionReply `json:"abort,omitempty"`

	// TLSLog is the standard TLS log, if NBD_OPT_STARTTLS is accepted.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the NBD scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendAbort indicates that NBD_OPT_ABORT should be sent before closing.
	SendAbort bool `long:"send-abort" description:"Send NBD_OPT_ABORT before closing."`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("nbd", "Network Block Device (NBD)",
		"Read an NBD server's greeting. If the server supports fixed newstyle negotiation, "+
			"we'll send NBD_OPT_STARTTLS and negotiate a TLS connection.", 10809)
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
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// abort sends NBD_OPT_ABORT and reads the reply, which the server MAY leave
// out by closing the connection (NBD protocol, "Option types").
func abort(conn *Connection) (*OptionReply, error) {
	if err := conn.Send(optionRequest(optAbort)); err != nil {
		return nil, err
	}
	reply, err := conn.ReadOptionReply(optAbort)
	if reply == nil && errors.Is(err, io.EOF) {
		return nil, nil
	}
	return reply, err
}

// Scan performs the NBD scan.
//  1. Open a TCP connection to the target port (default 10809).
//  2. Read the greeting.
//  3. If the server supports fixed newstyle negotiation, send the client
//     flags and NBD_OPT_STARTTLS, read the reply, negotiate a TLS connection.
//  4. If --send-abort is set, send NBD_OPT_ABORT and read the reply.
//  5. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. NBD requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	nbdConn := Connection{Conn: conn}
	greeting, err := nbdConn.ReadGreeting()
	if err != nil {
		// Quit early if we didn't get a valid response, but keep a
		// truncated greeting of an NBD server.
		if len(greeting) < greetingMagicsSize || binary.BigEndian.Uint64(greeting[:8]) != nbdMagic {
			result = nil
		} else {
			result.Greeting = hex.EncodeToString(greeting)
		}
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read greeting from %s: %w", target.String(), err)
	}
	result.Greeting = hex.EncodeToString(greeting)
	if len(greeting) == greetingMagicsSize {
		result.Negotiation = negotiationOldstyle
		return zgrab2.SCAN_SUCCESS, result, nil
	}
	flags := binary.BigEndian.Uint16(greeting[greetingMagicsSize:])
	result.HandshakeFlags = &flags
	if flags&flagFixedNewstyle == 0 {
		result.Negotiation = negotiationNewstyle
	} else {
		result.Negotiation = negotiationFixedNewstyle
	}
	if flags&^(flagFixedNewstyle|flagNoZeroes) != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("NBD server for target %s set unknown handshake flags 0x%04x", target.String(), flags)
	}
	// The client MUST NOT send NBD_OPT_STARTTLS without fixed newstyle
	// negotiation (NBD protocol, "Client-side requirements").
	if flags&flagFixedNewstyle == 0 {
		return zgrab2.SCAN_SUCCESS, result, nil
	}

	if err = nbdConn.Send(startTLSRequest()); err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send NBD_OPT_STARTTLS: %w", err)
	}
	reply, err := nbdConn.ReadOptionReply(optStartTLS)
	result.StartTLS = reply
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read NBD_OPT_STARTTLS reply: %w", err)
	}
	// NBD_REP_ACK has no data ("Option reply types"); TLS-Attacker refuses one with data.
	if reply.ReplyType == repAck && reply.length != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("NBD_REP_ACK with %d bytes of data returned from NBD_OPT_STARTTLS", reply.length)
	}
	// Strictly NBD_REP_ACK, as TLS-Attacker requires; any other reply means
	// the server cannot or will not upgrade ("Client-side requirements").
	if reply.ReplyType != repAck {
		// The unread rest of a truncated reply would be taken for the reply
		// to NBD_OPT_ABORT.
		if scanner.config.SendAbort && reply.length <= maxReplyData {
			result.Abort, _ = abort(&nbdConn)
		}
		return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("NBD reply type 0x%08x (%s) returned from NBD_OPT_STARTTLS: %.128q", reply.ReplyType, reply.ReplyName, reply.Message)
	}
	tlsWrapper := dialGroup.TLSWrapper
	if tlsWrapper == nil {
		return zgrab2.SCAN_INVALID_INPUTS, result, errors.New("no TLS wrapper found. NBD with STARTTLS requires a TLS wrapper")
	}
	tlsConn, err := tlsWrapper(ctx, target, conn)
	if tlsConn != nil {
		result.TLSLog = tlsConn.GetLog()
	}
	if err != nil {
		return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
	}
	if scanner.config.SendAbort {
		result.Abort, err = abort(&Connection{Conn: tlsConn})
		if err != nil {
			return zgrab2.SCAN_POST_TLS_APPLICATION_ERROR, result, fmt.Errorf("could not abort over TLS: %w", err)
		}
		if result.Abort != nil && result.Abort.ReplyType != repAck {
			return zgrab2.SCAN_POST_TLS_APPLICATION_ERROR, result, fmt.Errorf("NBD reply type 0x%08x (%s) returned from NBD_OPT_ABORT", result.Abort.ReplyType, result.Abort.ReplyName)
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
