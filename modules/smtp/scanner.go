// Package smtp provides a zgrab2 module that scans for SMTP mail
// servers.
// Default Port: 25 (TCP)
//
// The --smtps command tells the scanner to wrap the entire connection
// in a TLS session.
//
// The --send-ehlo and --send-helo flags tell the scanner to first send
// the EHLO/HELO command; if a --ehlo-domain or --helo-domain is present
// that domain will be used, otherwise it is omitted.
// The EHLO and HELO flags are mutually exclusive.
//
// The --send-help flag tells the scanner to send a HELP command.
//
// The --starttls flag tells the scanner to send the STARTTLS command,
// and then negotiate a TLS connection.
// The scanner uses the standard TLS flags for the handshake.
//
// The --send-quit flag tells the scanner to send a QUIT command.
//
// So, if no flags are specified, the scanner simply reads the banner
// returned by the server and disconnects.
//
// The output contains the banner and the responses to any commands that
// were sent, and if --starttls or --smtps was sent, the standard TLS logs.
//
// With --sslv2, after the server accepts STARTTLS the scanner sends an SSL 2.0 CLIENT-HELLO
// (lib/sslv2) instead of the TLS handshake and stops after the reply; the
// outcome goes to the sslv2 field and is the scan status.
//
// With --lhlo-fallback (needs EHLO, e.g. --send-ehlo-override), an EHLO
// refused with 500 or 503 is followed by LHLO on the same connection. An LMTP
// server greets like SMTP but must not accept EHLO, 500 recommended (RFC 2033,
// section 4.1), so a 250 reply to LHLO identifies LMTP; its capabilities then
// decide STARTTLS, as the EHLO reply does for SMTP.
//
// With --ftp-fallback (needs EHLO, e.g. --send-ehlo-override), an EHLO
// refused with a 5xx reply is followed by AUTH TLS on the same connection, as
// TLS-Attacker opens FTP. An FTP server can greet with a bare 220 like SMTP;
// 234 grants AUTH TLS (RFC 4217, section 4) and is no SMTP reply code, so the
// server is marked FTP and the TLS handshake follows. Otherwise FEAT is sent:
// 211 (RFC 2389, section 3.2) marks an FTP server, which is sent AUTH TLS once
// more if it refused with 503, as TLS-Attacker retries after discovery. An FTP
// server without AUTH TLS ends like an SMTP server without STARTTLS.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/sslv2"
)

// FTP replies as TLS-Attacker matches them (FTP: AUTH TLS ^234 , FEAT ^211 ):
// AUTH TLS granted (RFC 4217, section 4), and FEAT listing features or saying
// there are none (RFC 2389, section 3.2).
var (
	authTLSOKRegex   = regexp.MustCompile(`(?m)^234 `)
	featOKRegex      = regexp.MustCompile(`(?m)^211 `)
	badSequenceRegex = regexp.MustCompile(`^503 `)
)

// ErrInvalidResponse is returned when the server returns an invalid or unexpected response.
var ErrInvalidResponse = zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid response for SMTP"))

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the string sent by the server immediately after connecting.
	Banner string `json:"banner,omitempty"`

	// HELO is the server's response to the HELO command, if one is sent.
	HELO string `json:"helo,omitempty"`

	// EHLO is the server's response to the EHLO command, if one is sent.
	EHLO string `json:"ehlo,omitempty"`

	// LHLO is the server's response to the LHLO command, sent with
	// --lhlo-fallback after EHLO is refused.
	LHLO string `json:"lhlo,omitempty"`

	// LMTP is true if the server accepted LHLO (code 250), i.e. it speaks LMTP.
	LMTP bool `json:"lmtp,omitempty"`

	// FEAT is the server's response to the FEAT command, sent with
	// --ftp-fallback after EHLO and AUTH TLS are refused.
	FEAT string `json:"feat,omitempty"`

	// FTP is true if the server granted AUTH TLS (234) or answered FEAT
	// with 211, i.e. it speaks FTP.
	FTP bool `json:"ftp,omitempty"`

	// AuthTLS is the response to the AUTH TLS command, sent with
	// --ftp-fallback after EHLO is refused (the last one if sent twice).
	AuthTLS string `json:"auth_tls,omitempty"`

	// HELP is the server's response to the HELP command, if it is sent.
	HELP string `json:"help,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// QUIT is the server's response to the QUIT command, if it is sent.
	QUIT string `json:"quit,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTls
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent or if --SMTPS is used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`

	// SSLv2 is the reply to the SSL 2.0 CLIENT-HELLO sent instead of the TLS
	// handshake, if --sslv2 is used.
	SSLv2 *sslv2.UpgradeResult `json:"sslv2,omitempty"`
}

// Flags holds the command-line configuration for the HTTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendHELP indicates that the client should send the HELP command (after HELO/EHLO).
	SendHELP bool `long:"send-help" description:"Send the HELP command"`

	// SendQUIT indicates that the QUIT command should be set.
	SendQUIT bool `long:"send-quit" description:"Send the QUIT command before closing."`

	// SendEHLOOverride indicates that regardless of if the server says it supports ESMTP, we should send an EHLO
	SendEHLOOverride bool `long:"send-ehlo-override" description:"Send the EHLO command regardless of if the server supports ESMTP"`

	// SendHELOOverride indicates that the client should send the HELO command, regardless of if the server supports ESMTP.
	SendHELOOverride bool `long:"send-helo-override" description:"Send the HELO command regardless of if the server supports ESMTP or not"`

	// SendSTARTTLSOverride indicates that the client should send the STARTTLS command, regardless of if the server supports it with ESMTP
	SendSTARTTLSOverride bool `long:"send-starttls-override" description:"Send the STARTTLS command regardless of if the server advertises support in ESMTP"`

	// SMTPSecure indicates that the entire transaction should be wrapped in a TLS session.
	SMTPSecure bool `long:"smtps" description:"Perform a TLS handshake immediately upon connecting."`

	// SSLv2 sends an SSL 2.0 CLIENT-HELLO instead of the TLS handshake after the upgrade.
	SSLv2 bool `long:"sslv2" description:"After the server accepts STARTTLS, send an SSL 2.0 CLIENT-HELLO instead of the TLS handshake and stop after its reply"`

	// EHLODomain is the client domain sent with EHLO; empty falls back to the target domain.
	EHLODomain string `long:"ehlo-domain" description:"Client domain to send with the EHLO command (default: target domain)"`

	// LHLOFallback sends LHLO after EHLO is refused, to recognize LMTP servers.
	LHLOFallback bool `long:"lhlo-fallback" description:"If EHLO is refused with 500 or 503, send LHLO (with the EHLO domain) to recognize an LMTP server (RFC 2033); needs EHLO, e.g. --send-ehlo-override"`

	// FTPFallback sends AUTH TLS (then FEAT) after EHLO is refused, to recognize FTP servers.
	FTPFallback bool `long:"ftp-fallback" description:"If EHLO is refused with a 5xx reply, send AUTH TLS, then FEAT if refused; 234 (RFC 4217) or 211 (RFC 2389) marks an FTP server, whose AUTH TLS replaces STARTTLS; needs --send-ehlo-override"`

	// HELODomain is the client domain sent with HELO; empty falls back to the target domain.
	HELODomain string `long:"helo-domain" description:"Client domain to send with the HELO command (default: target domain)"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("smtp", "Simple Mail Transfer Protocol (SMTP)",
		"Fetch an SMTP server banner, optionally over TLS. By default, if the server advertises support for ESMTP in "+
			"the banner, we'll send an EHLO command and an HELO command otherwise. If the server advertises support for "+
			"STARTTLS, we'll send that command and negotiate a TLS connection. "+
			"This can be overridden with the various override flags.", 25)
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
	if flags.SendSTARTTLSOverride && flags.SMTPSecure {
		return errors.New("cannot use --smtps and --send-starttls-override at the same time")
	}
	if flags.SendEHLOOverride && flags.SendHELOOverride {
		return errors.New("cannot use --send-helo-override with --send-ehlo-override. Please choose one")
	}
	if flags.SSLv2 && flags.SMTPSecure {
		return errors.New("cannot use --smtps and --sslv2 at the same time")
	}
	if flags.FTPFallback && !flags.SendEHLOOverride {
		// an FTP greeting never says ESMTP, so without the override HELO is sent
		return errors.New("--ftp-fallback needs --send-ehlo-override: AUTH TLS follows a refused EHLO")
	}
	if flags.FTPFallback && flags.SMTPSecure {
		return errors.New("cannot use --ftp-fallback with --smtps")
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

func (scanner *Scanner) GetScanMetadata() any {
	return &moduleMetadata
}

func getSMTPCode(response string) (int, error) {
	if len(response) < 5 {
		return 0, ErrInvalidResponse
	}
	ret, err := strconv.Atoi(response[0:3])
	if err != nil {
		return 0, ErrInvalidResponse
	}
	return ret, nil
}

// Get a command with an optional argument (so if the argument is absent, there is no trailing space)
func getCommand(cmd string, arg string) string {
	if arg == "" {
		return cmd
	}
	return cmd + " " + arg
}

// Verify that an SMTP code was returned, and that it is a successful one!
// Return code on SCAN_APPLICATION_ERROR for better info
func VerifySMTPContents(banner string) (zgrab2.ScanStatus, int) {
	code, err := getSMTPCode(banner)
	lowerBanner := strings.ToLower(banner)
	switch {
	case err == nil && (code < 200 || code >= 300):
		return zgrab2.SCAN_APPLICATION_ERROR, code
	case err == nil,
		strings.Contains(banner, "SMTP"),
		strings.Contains(lowerBanner, "blacklist"),
		strings.Contains(lowerBanner, "abuse"),
		strings.Contains(lowerBanner, "rbl"),
		strings.Contains(lowerBanner, "spamhaus"),
		strings.Contains(lowerBanner, "relay"):
		return zgrab2.SCAN_SUCCESS, 0
	default:
		return zgrab2.SCAN_PROTOCOL_ERROR, 0
	}
}

// Scan performs the SMTP scan.
//  1. Open a TCP connection to the target port (default 25).
//  2. If --smtps is set, perform a TLS handshake.
//  3. Read the banner.
//  4. If --send-ehlo or --send-helo is sent, send the corresponding EHLO
//     or HELO command.
//  5. If --send-help is sent, send HELP, read the result.
//  6. If --starttls is sent, send STARTTLS, read the result, negotiate a
//     TLS connection.
//  7. If --send-quit is sent, send QUIT and read the result.
//  8. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. SMTP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	// tlsActive is set to true once a TLS handshake has succeeded, causing
	// subsequent application-layer errors to map to SCAN_POST_TLS_APPLICATION_ERROR
	// instead of SCAN_APPLICATION_ERROR.
	tlsActive := false
	appErrStatus := func() zgrab2.ScanStatus {
		if tlsActive {
			return zgrab2.SCAN_POST_TLS_APPLICATION_ERROR
		}

		return zgrab2.SCAN_APPLICATION_ERROR
	}

	if scanner.config.SMTPSecure {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. SMTP with SMTPSecure requires a TLS wrapper")
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
		tlsActive = true
		conn = tlsConn
	}
	smtpConn := Connection{Conn: conn}
	banner, err := smtpConn.ReadResponse()
	if err != nil {
		if !scanner.config.SMTPSecure {
			result = nil
		}

		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read response from %s: %w", target.String(), err)
	}
	// Quit early if we didn't get a valid response
	// OR save response to return later
	sr, bannerResponseCode := VerifySMTPContents(banner)
	if sr == zgrab2.SCAN_PROTOCOL_ERROR {
		return sr, nil, fmt.Errorf("invalid response for SMTP: %s", banner)
	}
	if tlsActive && sr == zgrab2.SCAN_APPLICATION_ERROR {
		sr = zgrab2.SCAN_POST_TLS_APPLICATION_ERROR
	}
	result.Banner = banner
	serverSupportsEHLO := strings.Contains(result.Banner, "ESMTP")
	// send EHLO if the server supports it, or if we are overriding the default behavior
	shouldSendEHLO := !scanner.config.SendHELOOverride && (serverSupportsEHLO || scanner.config.SendEHLOOverride)
	if shouldSendEHLO {
		// server supports EHLO, use Extended Hello
		domain := scanner.config.EHLODomain
		if domain == "" {
			domain = target.Domain
		}
		ret, err := smtpConn.SendCommand(getCommand("EHLO", domain))
		if err != nil {
			return appErrStatus(), result, fmt.Errorf("could not send EHLO command: %w", err)
		}
		result.EHLO = ret
		moduleMetadata.incrementHostsSupportingEHLO() // mark that we found a host that supports EHLO
		// An LMTP server answers EHLO with an error, 500 recommended (RFC 2033,
		// section 4.1); 500 and 503 are the refusals TLS-Attacker answers with
		// a retry (SMTP BAD_SEQUENCE_REGEX ^50[03]).
		if code, codeErr := getSMTPCode(ret); scanner.config.LHLOFallback && codeErr == nil && (code == 500 || code == 503) {
			// LHLO is only a probe: if it cannot be sent (the server closed
			// after refusing EHLO), the result stays that of an SMTP server.
			if lhlo, lhloErr := smtpConn.SendCommand(getCommand("LHLO", domain)); lhloErr == nil {
				result.LHLO = lhlo
				if code, codeErr = getSMTPCode(lhlo); codeErr == nil && code == 250 {
					result.LMTP = true
				}
			}
		}
		// An FTP server answers EHLO with an error (FileZilla 500 or 501,
		// vsftpd and Apache FtpServer 530).
		if code, codeErr := getSMTPCode(ret); scanner.config.FTPFallback && !result.LMTP && codeErr == nil && code >= 500 && code < 600 {
			if err := scanner.probeFTP(&smtpConn, result); err != nil {
				return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send AUTH TLS command: %w", err)
			}
		}
	} else {
		// send a HELO msg since server doesn't support EHLO
		domain := scanner.config.HELODomain
		if domain == "" {
			domain = target.Domain
		}
		ret, err := smtpConn.SendCommand(getCommand("HELO", domain))
		if err != nil {
			return appErrStatus(), result, fmt.Errorf("could not send HELO command: %w", err)
		}
		result.HELO = ret
		moduleMetadata.incrementHostsSupportingHELO() // mark that we found a host that supports HELO
	}
	// HELP would break an accepted AUTH TLS, which wants the handshake next
	if scanner.config.SendHELP && !result.FTP {
		ret, err := smtpConn.SendCommand("HELP")
		if err != nil {
			return appErrStatus(), result, fmt.Errorf("could not send HELP command: %w", err)
		}
		result.HELP = ret
	}
	serverSupportsSTARTTLS := strings.Contains(result.EHLO, "STARTTLS")
	if result.LMTP {
		serverSupportsSTARTTLS = lhloSupportsSTARTTLS(result.LHLO)
	}
	shouldSendSTARTTLS := scanner.config.SendSTARTTLSOverride || serverSupportsSTARTTLS
	// An FTP server was sent AUTH TLS by probeFTP; it is upgraded only if it
	// granted it, and gets no STARTTLS
	ftpUpgrade := result.FTP && authTLSOKRegex.MatchString(result.AuthTLS)
	if result.FTP {
		shouldSendSTARTTLS = ftpUpgrade
	}
	// If the server supports STARTTLS or user requests STARTTLS, and we haven't already negotiated a TLS connection
	if shouldSendSTARTTLS && !scanner.config.SMTPSecure {
		if !ftpUpgrade {
			ret, err := smtpConn.SendCommand("STARTTLS")
			if err != nil {
				return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send STARTTLS command: %w", err)
			}
			result.StartTLS = ret
			code, err := getSMTPCode(ret)
			if err != nil {
				return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not get STARTTLS command code: %w", err)
			}
			if code < 200 || code >= 300 {
				return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("SMTP error code %d returned from STARTTLS command (%s)", code, strings.TrimSpace(ret))
			}
		}
		// SSL 2.0 after either upgrade: STARTTLS, or AUTH TLS of an FTP server
		if scanner.config.SSLv2 {
			status, upgrade, sslv2Err := sslv2.ProbeUpgrade(smtpConn.Conn)
			result.SSLv2 = upgrade
			return status, result, sslv2Err
		}
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. SMTP with SMTPSecure requires a TLS wrapper")
		}
		tlsConn, err := tlsWrapper(ctx, target, smtpConn.Conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
		tlsActive = true
		smtpConn.Conn = tlsConn
		moduleMetadata.incrementHostsSupportingSTARTTLS() // mark that we found a host that supports STARTTLS
	}
	if scanner.config.SendQUIT {
		ret, err := smtpConn.SendCommand("QUIT")
		if err != nil {
			return appErrStatus(), result, fmt.Errorf("could not send QUIT command: %w", err)
		}
		result.QUIT = ret
	}
	if sr == zgrab2.SCAN_APPLICATION_ERROR || sr == zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
		return sr, result, fmt.Errorf("SMTP error code %d returned in banner grab for target %s", bannerResponseCode, target.String())
	}

	return sr, result, nil
}

// lhloSupportsSTARTTLS reports whether an LHLO reply lists the STARTTLS
// keyword: the first word of a line after the first (domain) line, matched
// case-insensitively (RFC 5321, section 4.1.1.1), as the lmtp module does.
func lhloSupportsSTARTTLS(lhlo string) bool {
	lines := strings.Split(strings.TrimSuffix(lhlo, "\r\n"), "\r\n")
	for _, line := range lines[1:] {
		if len(line) < 4 {
			continue
		}
		fields := strings.Fields(line[4:])
		if len(fields) > 0 && strings.EqualFold(fields[0], "STARTTLS") {
			return true
		}
	}
	return false
}

// probeFTP sends AUTH TLS to a server that refused EHLO, then FEAT if AUTH
// TLS is refused, and AUTH TLS once more if FEAT shows an FTP server and the
// refusal was 503; this is TLS-Attacker's FTP sequence (AUTH TLS, FEAT
// discovery and retry on its bad-sequence reply ^503 ). The first two commands
// are only a probe: if one cannot be sent (the server closed the connection),
// the result stays that of an SMTP server. Only a failed retry, to a server
// known to be FTP, is an error.
func (scanner *Scanner) probeFTP(conn *Connection, result *ScanResults) error {
	ret, err := conn.SendCommand("AUTH TLS")
	if err != nil {
		return nil
	}
	result.AuthTLS = ret
	if authTLSOKRegex.MatchString(ret) {
		result.FTP = true
		return nil
	}
	feat, err := conn.SendCommand("FEAT")
	if err != nil {
		return nil
	}
	result.FEAT = feat
	if !featOKRegex.MatchString(feat) {
		return nil
	}
	result.FTP = true
	if !badSequenceRegex.MatchString(ret) {
		return nil
	}
	if ret, err = conn.SendCommand("AUTH TLS"); err != nil {
		return err
	}
	result.AuthTLS = ret
	return nil
}
