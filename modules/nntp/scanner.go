// Package nntp provides a zgrab2 module that scans for NNTP servers.
// Default Port: 119 (TCP)
//
// The scanner reads the server's greeting, then sends CAPABILITIES. If the
// server lists the STARTTLS capability (RFC 4642), the scanner sends STARTTLS
// and, on the 382 reply, negotiates a TLS connection. The
// --send-starttls-override flag sends STARTTLS even when it is not advertised.
// The scanner uses the standard TLS flags for the handshake.
//
// The --nntps flag tells the scanner to wrap the entire connection in a TLS
// session. --nntps does not change the default port number from 119, so it
// should usually be coupled with e.g. --port 563 (the "nntps" port from
// RFC 4642, Section 1).
//
// Status codes may be followed by text or stand alone (RFC 3977,
// Section 9.4.1), so the scanner accepts e.g. a bare "382" CRLF, whereas
// TLS-Attacker requires a space after the code. Lines must end in CRLF
// (RFC 3977, Section 3.1); a server ending them in a bare LF times out.
//
// The scanner does not send MODE READER, so a mode-switching server in transit
// mode (which lists MODE-READER but not STARTTLS) is reported without STARTTLS.
//
// The output contains the server's greeting and its responses to CAPABILITIES
// and to STARTTLS, and if STARTTLS was negotiated or --nntps was set, the
// standard TLS logs.
package nntp

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
var ErrInvalidResponse = zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid response for NNTP"))

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the server's greeting.
	Banner string `json:"banner,omitempty"`

	// Capabilities is the server's response to the CAPABILITIES command.
	Capabilities string `json:"capabilities,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTLS
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent or if --nntps is used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the NNTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendSTARTTLSOverride indicates that the client should send the STARTTLS command, regardless of if the server advertises the STARTTLS capability
	SendSTARTTLSOverride bool `long:"send-starttls-override" description:"Send the STARTTLS command regardless of if the server advertises the STARTTLS capability in CAPABILITIES"`

	// NNTPSecure indicates that the entire transaction should be wrapped in a TLS session.
	NNTPSecure bool `long:"nntps" description:"Perform a TLS handshake immediately upon connecting."`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("nntp", "Network News Transfer Protocol (NNTP)",
		"Fetch an NNTP server banner and capabilities, optionally over TLS. If the server advertises STARTTLS, "+
			"we'll send STARTTLS and negotiate a TLS connection. "+
			"This can be overridden with the --send-starttls-override flag.", 119)
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
	if flags.SendSTARTTLSOverride && flags.NNTPSecure {
		return errors.New("cannot use --nntps and --send-starttls-override at the same time")
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

// statusRegex captures the three-digit status code that starts a response,
// followed by text or by the end of the line (RFC 3977, Section 9.4.1).
var statusRegex = regexp.MustCompile(`^(\d\d\d)(?: |\r\n)`)

// Status codes the scanner checks for.
const (
	// Greetings of a server that accepts commands (RFC 3977, Section 5.1.1).
	codePostingAllowed    = 200
	codePostingProhibited = 201
	// Greetings of a server that then closes the connection (RFC 3977,
	// Section 5.1.1); together with 200 and 201 the only valid greetings.
	codeServiceTemporarilyUnavailable = 400
	codeServicePermanentlyUnavailable = 502
	// Reply to CAPABILITIES carrying the capability list (RFC 3977, Section 5.2.1).
	codeCapabilityList = 101
	// Reply that grants STARTTLS (RFC 4642, Section 2.2.1); 502 and 580 refuse it.
	codeContinueWithTLS = 382
)

// getNNTPCode returns the status code of the response.
func getNNTPCode(response string) (int, error) {
	match := statusRegex.FindStringSubmatch(response)
	if match == nil {
		return 0, ErrInvalidResponse
	}
	ret, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, ErrInvalidResponse
	}
	return ret, nil
}

// supportsSTARTTLS reports whether a CAPABILITIES response is a capability
// list that includes the STARTTLS label. Only the lines of the data block are
// examined, not the 101 status line, and a capability line's first token is
// its (case-insensitive) label (RFC 3977, Section 3.3.1).
func supportsSTARTTLS(capabilities string) bool {
	if code, err := getNNTPCode(capabilities); err != nil || code != codeCapabilityList {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(capabilities, "\r\n"), "\r\n")
	for _, line := range lines[1:] {
		if line == "." {
			break
		}
		// Undo dot-stuffing (RFC 3977, Section 3.1.1).
		line = strings.TrimPrefix(line, ".")
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "STARTTLS") {
			return true
		}
	}
	return false
}

// Scan performs the NNTP scan.
//  1. Open a TCP connection to the target port (default 119).
//  2. If --nntps is set, perform a TLS handshake.
//  3. Read the greeting.
//  4. Send CAPABILITIES and read the response.
//  5. If the server advertises STARTTLS (or --send-starttls-override is set),
//     send STARTTLS, read the result, negotiate a TLS connection.
//  6. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. NNTP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	if scanner.config.NNTPSecure {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. NNTP with NNTPSecure requires a TLS wrapper")
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
		conn = tlsConn
	}
	nntpConn := Connection{Conn: conn}
	banner, err := nntpConn.ReadResponse(lineEndRegex)
	if err != nil {
		if !scanner.config.NNTPSecure {
			result = nil
		}

		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read banner from %s: %w", target.String(), err)
	}
	// Quit early if we didn't get a valid response
	code, err := getNNTPCode(banner)
	if err != nil || (code != codePostingAllowed && code != codePostingProhibited &&
		code != codeServiceTemporarilyUnavailable && code != codeServicePermanentlyUnavailable) {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("invalid response for NNTP: %s", banner)
	}
	result.Banner = banner
	if code == codeServiceTemporarilyUnavailable || code == codeServicePermanentlyUnavailable {
		sr := zgrab2.SCAN_APPLICATION_ERROR
		if scanner.config.NNTPSecure {
			sr = zgrab2.SCAN_POST_TLS_APPLICATION_ERROR
		}

		return sr, result, fmt.Errorf("NNTP server for target %s greeted with %d: %s", target.String(), code, strings.TrimSpace(banner))
	}
	capabilities, err := nntpConn.SendCommand("CAPABILITIES", capabilitiesEndRegex)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send CAPABILITIES command: %w", err)
	}
	result.Capabilities = capabilities
	shouldSendSTARTTLS := scanner.config.SendSTARTTLSOverride || supportsSTARTTLS(capabilities)
	// If the server supports STARTTLS or user requests STARTTLS, and we haven't already negotiated a TLS connection
	if shouldSendSTARTTLS && !scanner.config.NNTPSecure {
		var ret string
		ret, err = nntpConn.SendCommand("STARTTLS", lineEndRegex)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send STARTTLS command: %w", err)
		}
		result.StartTLS = ret
		code, err = getNNTPCode(ret)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not get STARTTLS command code: %w", err)
		}
		// Strictly 382, as TLS-Attacker requires, though RFC 3977, Section 3.2
		// would have a client treat any other 3xx as "OK so far".
		if code != codeContinueWithTLS {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("NNTP code %d returned from STARTTLS command (%s)", code, strings.TrimSpace(ret))
		}
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. NNTP with STARTTLS requires a TLS wrapper")
		}
		var tlsConn *zgrab2.TLSConnection
		tlsConn, err = tlsWrapper(ctx, target, nntpConn.Conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
