// Package xmpp provides a zgrab2 module that scans for XMPP servers.
// Default Port: 5222 (TCP), xmpp-client (RFC 6120, Section 14.7)
//
// The scanner opens a client-to-server stream (RFC 6120, Section 4.2) and
// reads the server's stream header and stream features. If the features list
// STARTTLS (RFC 6120, Section 5.4.1), the scanner sends the STARTTLS command
// and, on <proceed/>, negotiates a TLS connection (Sections 5.4.2 and 5.4.3).
// The scan ends with the TLS handshake: the stream restart that RFC 6120,
// Section 5.4.3.3 requires next is not sent, as TLS-Attacker does not send it
// either. The --send-starttls-override flag sends STARTTLS even when it is not
// listed; TLS-Attacker always sends it, so a server that accepts STARTTLS
// without listing it is found here only with that flag. The scanner uses the
// standard TLS flags for the handshake.
//
// The opening stream header is byte for byte TLS-Attacker's. Its 'to' must
// name a domain the server serves (RFC 6120, Section 4.7.2): the scanner
// sends --xmpp-domain, else the target's domain, else the target's IP
// address, as TLS-Attacker does when connecting to an IP address. Servers
// such as Prosody and ejabberd answer an IP address or a domain they do not
// serve with a host-unknown stream error (RFC 6120, Section 4.9.3.6) and do
// not reveal the domains they do serve, so without a domain STARTTLS cannot
// be seen; the stream error's condition is kept in the output to tell this
// apart from a server that does not offer STARTTLS. Like TLS-Attacker, which
// uses its hostname for both, the scanner sends --xmpp-domain as the TLS SNI,
// and verifies the certificate against it with --verify-server-certificate,
// unless --server-name or --no-sni is given (RFC 6120, Section 5.4.3.1; RFC
// 7590, Section 3.5).
//
// The STARTTLS feature is recognized in the default namespace declaration
// form every known server uses (<starttls xmlns='...xmpp-tls'/>); one with a
// namespace prefix is not, and needs --send-starttls-override.
//
// The --xmpps flag tells the scanner to wrap the entire connection in a TLS
// session, XMPP's direct TLS (XEP-0368), which never uses STARTTLS. XEP-0368
// asks clients to offer the ALPN protocol "xmpp-client", which servers sharing
// a port (e.g. 443) with other services need: add --next-protos xmpp-client.
// XEP-0368 assigns no port, but 5223, used by the old-style SSL convention, is
// common; --xmpps does not change the default port number from 5222, so it
// should usually be coupled with that server's --port.
//
// Only client-to-server streams (jabber:client) are opened, as by
// TLS-Attacker; a server-to-server port (5269) answers them with a stream
// error.
//
// A stream error, or a stream that ends or stalls before its features, is
// reported as an application error with the server's reply kept; a reply that
// is not an XMPP stream is a protocol error.
//
// The output contains the server's reply to the opening stream header, its
// stream features and stream error condition (if any), its response to
// STARTTLS (if sent), and if STARTTLS was negotiated or --xmpps was set, the
// standard TLS logs.
//
// With --sslv2, after the server accepts STARTTLS the scanner sends an SSL 2.0 CLIENT-HELLO
// (lib/sslv2) instead of the TLS handshake and stops after the reply; the
// outcome goes to the sslv2 field and is the scan status.
package xmpp

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

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the server's reply to the opening stream header: its stream
	// header followed by the stream features or a stream error.
	Banner string `json:"banner,omitempty"`

	// Features is the stream features element, if the server sent one.
	Features string `json:"features,omitempty"`

	// STARTTLSRequired is true if the STARTTLS feature is marked
	// mandatory-to-negotiate with <required/> (RFC 6120, Section 5.4.1).
	STARTTLSRequired bool `json:"starttls_required,omitempty"`

	// StreamError is the defined condition of a stream error the server
	// sent, e.g. host-unknown (RFC 6120, Section 4.9.3).
	StreamError string `json:"stream_error,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTLS
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent or if --xmpps is used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`

	// SSLv2 is the reply to the SSL 2.0 CLIENT-HELLO sent instead of the TLS
	// handshake, if --sslv2 is used.
	SSLv2 *sslv2.UpgradeResult `json:"sslv2,omitempty"`
}

// Flags holds the command-line configuration for the XMPP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendSTARTTLSOverride indicates that the client should send the STARTTLS command, regardless of if the server advertises support in its stream features
	SendSTARTTLSOverride bool `long:"send-starttls-override" description:"Send the STARTTLS command regardless of if the server advertises support in its stream features"`

	// XMPPSecure indicates that the entire transaction should be wrapped in a TLS session.
	XMPPSecure bool `long:"xmpps" description:"Perform a TLS handshake immediately upon connecting (direct TLS)."`

	// SSLv2 sends an SSL 2.0 CLIENT-HELLO instead of the TLS handshake after the upgrade.
	SSLv2 bool `long:"sslv2" description:"After the server accepts STARTTLS, send an SSL 2.0 CLIENT-HELLO instead of the TLS handshake and stop after its reply"`

	// XMPPDomain is the domain sent in the 'to' attribute of the stream header; empty falls back to the target domain, then to the target IP address.
	XMPPDomain string `long:"xmpp-domain" description:"Domain to send in the 'to' attribute of the stream header, and as SNI and certificate name unless --server-name or --no-sni is given (default: target domain, else target IP address)"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("xmpp", "Extensible Messaging and Presence Protocol (XMPP)",
		"Fetch an XMPP server's stream header and stream features, optionally over TLS. If the server advertises STARTTLS, we'll send STARTTLS "+
			"and negotiate a TLS connection. This can be overridden with the --send-starttls-override flag.", 5222)
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
	if flags.SendSTARTTLSOverride && flags.XMPPSecure {
		return errors.New("cannot use --xmpps and --send-starttls-override at the same time")
	}
	if flags.SSLv2 && flags.XMPPSecure {
		return errors.New("cannot use --xmpps and --sslv2 at the same time")
	}
	return nil
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	// The 'to' domain doubles as SNI, as in TLS-Attacker.
	if f.XMPPDomain != "" && f.ServerName == "" && !f.NoSNI {
		f.ServerName = f.XMPPDomain
	}
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// streamOpening is TLS-Attacker's opening stream header; "%s" is the domain
// in 'to' (RFC 6120, Section 4.7.2). There is no 'from', as the client has
// no JID before authenticating (Section 4.7.1).
const streamOpening = "<?xml version='1.0'?><stream:stream to='%s' version='1.0' xmlns='jabber:client'" +
	" xmlns:stream='http://etherx.jabber.org/streams'>"

// commandSTARTTLS is the STARTTLS command (RFC 6120, Section 5.4.2.1).
const commandSTARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

var (
	// streamHeaderRegex matches the server's stream header.
	streamHeaderRegex = regexp.MustCompile(`<stream:stream\b[^>]*>`)
	// prefixedHeaderRegex matches a stream header with any prefix.
	prefixedHeaderRegex = regexp.MustCompile(`<[^\s:/>]+:stream\b[^>]*>`)
	// streamNamespaceRegex matches the stream namespace bound to any prefix,
	// to tell a stream with another prefix from a reply that is not XMPP.
	streamNamespaceRegex = regexp.MustCompile(`xmlns:[^\s=]+\s*=\s*(?:'http://etherx\.jabber\.org/streams'|"http://etherx\.jabber\.org/streams")`)
	// featuresRegex is TLS-Attacker's FEATURES_REGEX.
	featuresRegex = regexp.MustCompile(`(?s)<stream:features(?:\s*/>|\b.*?</stream:features>)`)
	// starttlsFeatureRegex matches the STARTTLS feature, qualified by the
	// xmpp-tls namespace in either quotes (RFC 6120, Section 5.4.1); group 1
	// is its content.
	starttlsFeatureRegex = regexp.MustCompile(`(?s)<starttls\s[^>]*?\bxmlns\s*=\s*(?:'urn:ietf:params:xml:ns:xmpp-tls'|"urn:ietf:params:xml:ns:xmpp-tls")[^>]*?(?:/>|>(.*?)</starttls>)`)
	// requiredRegex matches <required/> in the STARTTLS feature's content.
	requiredRegex = regexp.MustCompile(`<required\b`)
	// proceedRegex is TLS-Attacker's PROCEED_REGEX (RFC 6120, Section 5.4.2.3).
	proceedRegex = regexp.MustCompile(`<proceed\b[^>]*?(?:/>|>\s*</proceed>)`)
	// streamErrorRegex matches a stream error; group 1 is its content, up to
	// its end or the end of the reply (RFC 6120, Section 4.9.2).
	streamErrorRegex = regexp.MustCompile(`(?s)<stream:error\b[^>]*?(?:/>|>(.*?)(?:</stream:error>|$))`)
	// elementNameRegex matches the local name (without a prefix) of each
	// element that starts in a text.
	elementNameRegex = regexp.MustCompile(`<(?:[^\s/>!?:]+:)?([^\s/>!?:]+)`)
)

// xmlEscaper escapes what may not appear in a single-quoted attribute value.
var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", "'", "&apos;")

// getStreamError returns the condition of the stream error in response, or
// "" if there is none. The condition is the first child of <stream:error/>
// other than the optional <text/> (RFC 6120, Section 4.9.2); its namespace is
// not checked, and an error without one is reported as "unknown".
func getStreamError(response string) string {
	match := streamErrorRegex.FindStringSubmatch(response)
	if match == nil {
		return ""
	}
	for _, name := range elementNameRegex.FindAllStringSubmatch(match[1], -1) {
		if name[1] != "text" {
			return name[1]
		}
	}
	return "unknown"
}

// Scan performs the XMPP scan.
//  1. Open a TCP connection to the target port (default 5222).
//  2. If --xmpps is set, perform a TLS handshake.
//  3. Send the opening stream header and read the server's stream header and
//     stream features.
//  4. If the server advertises STARTTLS (or --send-starttls-override is set),
//     send STARTTLS, read the result, negotiate a TLS connection.
//  5. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. XMPP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	// appErrStatus maps an application-layer refusal to
	// SCAN_POST_TLS_APPLICATION_ERROR once --xmpps has negotiated TLS.
	appErrStatus := zgrab2.SCAN_APPLICATION_ERROR
	if scanner.config.XMPPSecure {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. XMPP with XMPPSecure requires a TLS wrapper")
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
	xmppConn := Connection{Conn: conn}
	domain := scanner.config.XMPPDomain
	if domain == "" {
		domain = target.Domain
	}
	if domain == "" {
		domain = target.Host()
	}
	banner, err := xmppConn.SendCommand(fmt.Sprintf(streamOpening, xmlEscaper.Replace(domain)), openingEndRegex)
	if err != nil {
		status := zgrab2.TryGetScanStatus(err)
		err = fmt.Errorf("could not read stream header from %s: %w", target.String(), err)
		if !scanner.config.XMPPSecure {
			return status, nil, err
		}
		return status, result, err
	}
	if !streamHeaderRegex.MatchString(banner) {
		// A whole stream header with another prefix is XMPP, but cannot be
		// scanned like one; keep its reply.
		if !prefixedHeaderRegex.MatchString(banner) || !streamNamespaceRegex.MatchString(banner) {
			err = fmt.Errorf("invalid response for XMPP: %s", banner)
			if !scanner.config.XMPPSecure {
				return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
			}
			return zgrab2.SCAN_PROTOCOL_ERROR, result, err
		}
		result.Banner = banner
		return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("XMPP stream from %s does not use the stream prefix", target.String())
	}
	result.Banner = banner
	if result.StreamError = getStreamError(banner); result.StreamError != "" {
		return appErrStatus, result, fmt.Errorf("XMPP server for target %s sent stream error %s", target.String(), result.StreamError)
	}
	// Without features (e.g. a pre-1.0 server, RFC 6120, Section 4.7.5, or
	// a stream closed or stalled) STARTTLS cannot be negotiated.
	result.Features = featuresRegex.FindString(banner)
	if result.Features == "" {
		return appErrStatus, result, fmt.Errorf("XMPP server for target %s sent no stream features", target.String())
	}
	advertised := false
	if match := starttlsFeatureRegex.FindStringSubmatch(result.Features); match != nil {
		advertised = true
		result.STARTTLSRequired = requiredRegex.MatchString(match[1])
	}
	// If the server supports STARTTLS or user requests STARTTLS, and we haven't already negotiated a TLS connection
	if (scanner.config.SendSTARTTLSOverride || advertised) && !scanner.config.XMPPSecure {
		var ret string
		ret, err = xmppConn.SendCommand(commandSTARTTLS, upgradeEndRegex)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send STARTTLS command: %w", err)
		}
		result.StartTLS = ret
		// Strictly <proceed/>, as TLS-Attacker requires; <failure/> refuses
		// (RFC 6120, Section 5.4.2.2).
		if !proceedRegex.MatchString(ret) {
			result.StreamError = getStreamError(ret)
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("XMPP server for target %s did not proceed with STARTTLS: %s", target.String(), strings.TrimSpace(ret))
		}
		if scanner.config.SSLv2 {
			var status zgrab2.ScanStatus
			status, result.SSLv2, err = sslv2.ProbeUpgrade(xmppConn.Conn)
			return status, result, err
		}
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. XMPP with STARTTLS requires a TLS wrapper")
		}
		var tlsConn *zgrab2.TLSConnection
		tlsConn, err = tlsWrapper(ctx, target, xmppConn.Conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
