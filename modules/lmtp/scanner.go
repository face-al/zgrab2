// Package lmtp provides a zgrab2 module that scans for LMTP servers.
// Default Port: 24 (TCP)
//
// LMTP (RFC 2033) has no TCP port of its own (Section 5 only forbids port 25);
// 24, the IANA "any private mail system" port, is where it is commonly run.
//
// The scanner reads the server's greeting, then sends LHLO, LMTP's EHLO
// (RFC 2033, Section 4.1). If the reply lists the STARTTLS keyword
// (RFC 3207, Section 4), the scanner sends STARTTLS and, on the 220 reply,
// negotiates a TLS connection. The --send-starttls-override flag sends
// STARTTLS even when it is not listed, but only after a 250 reply to LHLO;
// TLS-Attacker sends STARTTLS without sending LHLO, so a server that accepts
// STARTTLS without listing it is found here only with that flag, and one that
// refuses LHLO is not found here at all. The scanner uses the standard TLS
// flags for the handshake.
//
// The --lmtps flag tells the scanner to wrap the entire connection in a TLS
// session. No port or service name is registered for LMTP over implicit TLS,
// but servers run it (e.g. Dovecot with ssl on its LMTP listener). --lmtps
// does not change the default port number from 24, so it should usually be
// coupled with that server's --port.
//
// LHLO must name the client (RFC 5321, Section 4.1.1.1), so the scanner sends
// --lhlo-domain, else the target's domain, else the address literal of its
// own IP address (RFC 5321, Section 4.1.3); a bare LHLO is refused (e.g. 501
// by Dovecot) and would hide STARTTLS.
//
// Reply codes may be followed by text or stand alone (RFC 5321, Section 4.2),
// so the scanner accepts e.g. a bare "220" CRLF, as TLS-Attacker does. Lines
// must end in CRLF (RFC 5321, Section 2.3.8); a server ending them in a bare
// LF times out.
//
// A greeting with any 4xx or 5xx code (RFC 5321, Sections 3.1 and 4.2.3 name
// 421 and 554) is reported as an application error with the greeting kept, as
// TLS-Attacker aborts on any such reply.
//
// The output contains the server's greeting, its responses to LHLO and
// STARTTLS (if sent), and if STARTTLS was negotiated or --lmtps was set, the
// standard TLS logs.
package lmtp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
)

// ErrInvalidResponse is returned when the server returns an invalid or unexpected response.
var ErrInvalidResponse = zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid response for LMTP"))

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the server's greeting.
	Banner string `json:"banner,omitempty"`

	// LHLO is the server's response to the LHLO command.
	LHLO string `json:"lhlo,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTLS
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent or if --lmtps is used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the LMTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendSTARTTLSOverride indicates that the client should send the STARTTLS command, regardless of if the server advertises support in LHLO
	SendSTARTTLSOverride bool `long:"send-starttls-override" description:"Send the STARTTLS command regardless of if the server advertises support in LHLO"`

	// LMTPSecure indicates that the entire transaction should be wrapped in a TLS session.
	LMTPSecure bool `long:"lmtps" description:"Perform a TLS handshake immediately upon connecting."`

	// LHLODomain is the client domain sent with LHLO; empty falls back to the target domain, then to our IP address literal.
	LHLODomain string `long:"lhlo-domain" description:"Client domain to send with the LHLO command (default: target domain, else our IP address literal)"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("lmtp", "Local Mail Transfer Protocol (LMTP)",
		"Fetch an LMTP server banner and LHLO response, optionally over TLS. If the server advertises STARTTLS, we'll send STARTTLS "+
			"and negotiate a TLS connection. This can be overridden with the --send-starttls-override flag.", 24)
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
	if flags.SendSTARTTLSOverride && flags.LMTPSecure {
		return errors.New("cannot use --lmtps and --send-starttls-override at the same time")
	}
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

// lineCodeRegex captures the three-digit code that starts the last line of a
// reply, followed by text or by the end of the line (RFC 5321, Section 4.2).
var lineCodeRegex = regexp.MustCompile(`^(\d\d\d)(?: |$)`)

// Reply codes the scanner checks for.
const (
	// Greeting of a server that accepts commands; also the reply that grants
	// STARTTLS (RFC 3207, Section 4).
	codeServiceReady = 220
	// Reply to a successful LHLO (RFC 2033, Section 4.1; RFC 5321, Section 4.1.1.1).
	codeOK = 250
)

// getLMTPCode returns the code of the reply, taken from its last line; all
// lines of a multiline reply carry the same code (RFC 5321, Section 4.2.1).
func getLMTPCode(response string) (int, error) {
	lines := strings.Split(strings.TrimSuffix(response, "\r\n"), "\r\n")
	match := lineCodeRegex.FindStringSubmatch(lines[len(lines)-1])
	if match == nil {
		return 0, ErrInvalidResponse
	}
	ret, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, ErrInvalidResponse
	}
	return ret, nil
}

// keywordSTARTTLS is the LHLO keyword that advertises STARTTLS (RFC 3207, Section 4).
const keywordSTARTTLS = "STARTTLS"

// supportsSTARTTLS reports whether a successful LHLO reply lists the STARTTLS
// keyword. The first line holds the server's domain, not a keyword, and a
// keyword line's first token is its (case-insensitive) keyword (RFC 5321,
// Section 4.1.1.1).
func supportsSTARTTLS(lhlo string) bool {
	if code, err := getLMTPCode(lhlo); err != nil || code != codeOK {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(lhlo, "\r\n"), "\r\n")
	for _, line := range lines[1:] {
		if len(line) < 4 {
			continue
		}
		fields := strings.Fields(line[4:])
		if len(fields) > 0 && strings.EqualFold(fields[0], keywordSTARTTLS) {
			return true
		}
	}
	return false
}

// addressLiteral returns the address literal of addr's IP (RFC 5321,
// Section 4.1.3), or "" if addr is not a TCP address.
func addressLiteral(addr net.Addr) string {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil {
		return ""
	}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		return "[" + ip4.String() + "]"
	}
	// IP.String() leaves out the zone (tcpAddr.Zone), which the literal syntax lacks.
	return "[IPv6:" + tcpAddr.IP.String() + "]"
}

// Scan performs the LMTP scan.
//  1. Open a TCP connection to the target port (default 24).
//  2. If --lmtps is set, perform a TLS handshake.
//  3. Read the greeting.
//  4. Send LHLO and read the response.
//  5. If the server advertises STARTTLS (or --send-starttls-override is set),
//     send STARTTLS, read the result, negotiate a TLS connection.
//  6. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. LMTP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	// appErrStatus maps an application-layer refusal to
	// SCAN_POST_TLS_APPLICATION_ERROR once --lmtps has negotiated TLS.
	appErrStatus := zgrab2.SCAN_APPLICATION_ERROR
	if scanner.config.LMTPSecure {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. LMTP with LMTPSecure requires a TLS wrapper")
		}
		var tlsConn *zgrab2.TLSConnection
		tlsConn, err = tlsWrapper(ctx, target, conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
		result.ImplicitTLS = true
		appErrStatus = zgrab2.SCAN_POST_TLS_APPLICATION_ERROR
		conn = tlsConn
	}
	lmtpConn := Connection{Conn: conn}
	banner, err := lmtpConn.ReadResponse()
	if err != nil {
		if !scanner.config.LMTPSecure {
			result = nil
		}

		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read banner from %s: %w", target.String(), err)
	}
	// Quit early if we didn't get a valid response
	code, err := getLMTPCode(banner)
	// 4xx and 5xx refuse service, e.g. 421 and 554 (RFC 5321, Sections 3.1
	// and 4.2.3); TLS-Attacker aborts on any of them.
	if err != nil || (code != codeServiceReady && (code < 400 || code >= 600)) {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("invalid response for LMTP: %s", banner)
	}
	result.Banner = banner
	if code != codeServiceReady {
		return appErrStatus, result, fmt.Errorf("LMTP server for target %s greeted with %d: %s", target.String(), code, strings.TrimSpace(banner))
	}
	domain := scanner.config.LHLODomain
	if domain == "" {
		domain = target.Domain
	}
	if domain == "" {
		domain = addressLiteral(conn.LocalAddr())
	}
	lhlo, err := lmtpConn.SendCommand(strings.TrimSpace("LHLO " + domain))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send LHLO command: %w", err)
	}
	result.LHLO = lhlo
	code, err = getLMTPCode(lhlo)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not get LHLO command code: %w", err)
	}
	// 500 here means an SMTP server, which does not know LHLO (RFC 5321,
	// Section 4.2.4); LHLO tells the two apart (RFC 2033, Section 4.1).
	if code != codeOK {
		return appErrStatus, result, fmt.Errorf("LMTP code %d returned from LHLO command (%s)", code, strings.TrimSpace(lhlo))
	}
	// If the server supports STARTTLS or user requests STARTTLS, and we haven't already negotiated a TLS connection
	if (scanner.config.SendSTARTTLSOverride || supportsSTARTTLS(lhlo)) && !scanner.config.LMTPSecure {
		var ret string
		ret, err = lmtpConn.SendCommand("STARTTLS")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send STARTTLS command: %w", err)
		}
		result.StartTLS = ret
		code, err = getLMTPCode(ret)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not get STARTTLS command code: %w", err)
		}
		// Strictly 220, as TLS-Attacker requires; 454 and 501 refuse
		// (RFC 3207, Section 4).
		if code != codeServiceReady {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("LMTP code %d returned from STARTTLS command (%s)", code, strings.TrimSpace(ret))
		}
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. LMTP with STARTTLS requires a TLS wrapper")
		}
		var tlsConn *zgrab2.TLSConnection
		tlsConn, err = tlsWrapper(ctx, target, lmtpConn.Conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
