// Package irc provides a zgrab2 module that scans for IRC servers.
// Default Port: 6667 (TCP)
//
// The scanner opens with the IRCv3 capability negotiation command CAP LS. If
// the server lists the "tls" capability (the IRCv3 STARTTLS extension), the
// scanner sends STARTTLS before registering and, on the 670 (RPL_STARTTLS)
// reply, negotiates a TLS connection. The --send-starttls-override flag sends
// STARTTLS even when "tls" is not advertised.
// The scanner uses the standard TLS flags for the handshake.
//
// The --ircs flag tells the scanner to wrap the entire connection in a TLS
// session. --ircs does not change the default port number from 6667, so it
// should usually be coupled with e.g. --port 6697 (the "ircs-u" port from
// RFC 7194).
//
// The scanner never registers (no NICK/USER), so it does not join the network.
//
// The output contains the server's response to CAP LS and to STARTTLS, and
// if STARTTLS was negotiated or --ircs was set, the standard TLS logs.
package irc

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
var ErrInvalidResponse = zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid response for IRC"))

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// CapLS is the server's response to the CAP LS command, including any
	// lines (e.g. NOTICEs) the server sent before it.
	CapLS string `json:"cap_ls,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTLS
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent or if --ircs is used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the IRC scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendSTARTTLSOverride indicates that the client should send the STARTTLS command, regardless of if the server advertises the tls capability
	SendSTARTTLSOverride bool `long:"send-starttls-override" description:"Send the STARTTLS command regardless of if the server advertises the tls capability in CAP LS"`

	// IRCSecure indicates that the entire transaction should be wrapped in a TLS session.
	IRCSecure bool `long:"ircs" description:"Perform a TLS handshake immediately upon connecting."`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("irc", "Internet Relay Chat (IRC)",
		"Probe an IRC server with CAP LS, optionally over TLS. If the server advertises the IRCv3 tls capability, "+
			"we'll send STARTTLS and negotiate a TLS connection. "+
			"This can be overridden with the --send-starttls-override flag.", 6667)
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
	if flags.SendSTARTTLSOverride && flags.IRCSecure {
		return errors.New("cannot use --ircs and --send-starttls-override at the same time")
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

// ircLineRegex matches a line that is plausibly an IRC message from a server:
// a prefixed command or numeric (RFC 2812, Section 2.3.1), or one of the
// commands servers send without a prefix before registration.
var ircLineRegex = regexp.MustCompile(`^(?::\S+ (?:[A-Za-z]+|\d\d\d) |(?:NOTICE|PING|ERROR|CAP) )`)

// errorLineRegex matches an ERROR message, which a server sends right before
// closing the connection (RFC 2812, Section 3.7.4).
var errorLineRegex = regexp.MustCompile(`^(?::\S+ )?ERROR `)

// capLSLineRegex captures the capability list of a CAP LS line, whether it is
// the final line or a continuation line ("*" before the list). The list must be
// a ":" trailing parameter, matching what TLS-Attacker expects.
var capLSLineRegex = regexp.MustCompile(`^(?::\S+ )?CAP \S+ LS (?:\* )?:(.*)$`)

// numericLineRegex captures the three-digit code of a numeric reply.
var numericLineRegex = regexp.MustCompile(`^(?::\S+ )?(\d\d\d) `)

// rplStartTLS is the numeric a server sends to accept STARTTLS (RPL_STARTTLS);
// ERR_STARTTLS (691) signals failure.
const rplStartTLS = 670

// splitLines splits a response into lines ending in CRLF or a bare LF.
func splitLines(response string) []string {
	lines := strings.Split(strings.TrimRight(response, "\r\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// VerifyIRCContents checks that the response looks like it came from an IRC
// server, and that the server did not close the connection with an ERROR.
func VerifyIRCContents(response string) zgrab2.ScanStatus {
	isIRC := false
	for _, line := range splitLines(response) {
		if errorLineRegex.MatchString(line) {
			return zgrab2.SCAN_APPLICATION_ERROR
		}
		if ircLineRegex.MatchString(line) {
			isIRC = true
		}
	}
	if !isIRC {
		return zgrab2.SCAN_PROTOCOL_ERROR
	}
	return zgrab2.SCAN_SUCCESS
}

// supportsSTARTTLS reports whether a CAP LS response lists the "tls" capability.
func supportsSTARTTLS(capLS string) bool {
	for _, line := range splitLines(capLS) {
		match := capLSLineRegex.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		for _, capability := range strings.Fields(match[1]) {
			if capability == "tls" || strings.HasPrefix(capability, "tls=") {
				return true
			}
		}
	}
	return false
}

// getIRCCode returns the code of the numeric that ended the STARTTLS reply
// (startTLSEndRegex), or else the code of the last numeric reply in the response.
func getIRCCode(response string) (int, error) {
	code := ""
	if match := startTLSEndRegex.FindStringSubmatch(response); match != nil {
		code = match[1]
	}
	lines := splitLines(response)
	for i := len(lines) - 1; i >= 0 && code == ""; i-- {
		if match := numericLineRegex.FindStringSubmatch(lines[i]); match != nil {
			code = match[1]
		}
	}
	if code == "" {
		return 0, ErrInvalidResponse
	}
	ret, err := strconv.Atoi(code)
	if err != nil {
		return 0, ErrInvalidResponse
	}
	return ret, nil
}

// Scan performs the IRC scan.
//  1. Open a TCP connection to the target port (default 6667).
//  2. If --ircs is set, perform a TLS handshake.
//  3. Send CAP LS and read the response.
//  4. If the server advertises the tls capability (or --send-starttls-override
//     is set), send STARTTLS, read the result, negotiate a TLS connection.
//  5. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. IRC requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	if scanner.config.IRCSecure {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. IRC with IRCSecure requires a TLS wrapper")
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
	ircConn := Connection{Conn: conn}
	// Bare CAP LS, as TLS-Attacker sends it. A server may still split a long
	// capability list over several lines; capLSEndRegex waits for the final one.
	capLS, err := ircConn.SendCommand("CAP LS", capLSEndRegex)
	if err != nil {
		if !scanner.config.IRCSecure {
			result = nil
		}

		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read response from %s: %w", target.String(), err)
	}
	// Quit early if we didn't get a valid response
	sr := VerifyIRCContents(capLS)
	if sr == zgrab2.SCAN_PROTOCOL_ERROR {
		return sr, nil, fmt.Errorf("invalid response for IRC: %s", capLS)
	}
	result.CapLS = capLS
	if sr == zgrab2.SCAN_APPLICATION_ERROR {
		if scanner.config.IRCSecure {
			sr = zgrab2.SCAN_POST_TLS_APPLICATION_ERROR
		}

		return sr, result, fmt.Errorf("IRC server closed the connection for target %s: %s", target.String(), strings.TrimSpace(capLS))
	}
	shouldSendSTARTTLS := scanner.config.SendSTARTTLSOverride || supportsSTARTTLS(capLS)
	// If the server supports STARTTLS or user requests STARTTLS, and we haven't already negotiated a TLS connection
	if shouldSendSTARTTLS && !scanner.config.IRCSecure {
		ret, err := ircConn.SendCommand("STARTTLS", startTLSEndRegex)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send STARTTLS command: %w", err)
		}
		result.StartTLS = ret
		if VerifyIRCContents(ret) == zgrab2.SCAN_APPLICATION_ERROR {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("IRC server closed the connection after STARTTLS: %s", strings.TrimSpace(ret))
		}
		code, err := getIRCCode(ret)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not get STARTTLS command code: %w", err)
		}
		if code != rplStartTLS {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("IRC numeric %d returned from STARTTLS command (%s)", code, strings.TrimSpace(ret))
		}
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. IRC with STARTTLS requires a TLS wrapper")
		}
		tlsConn, err := tlsWrapper(ctx, target, ircConn.Conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
	}

	return sr, result, nil
}
