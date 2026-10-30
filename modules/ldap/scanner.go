// Package ldap provides a zgrab2 module that scans for LDAP servers.
// Default Port: 389 (TCP)
//
// The scanner reads the root DSE anonymously (a base-object search of the
// empty DN, RFC 4512 Section 5.1). If the server lists the StartTLS extended
// operation (1.3.6.1.4.1.1466.20037) in supportedExtension, the scanner sends
// the StartTLS request (RFC 4511 Section 4.14) and, on a success result,
// negotiates a TLS connection. The --send-starttls-override flag sends
// StartTLS even when it is not advertised, e.g. because the server refuses
// anonymous root DSE reads.
// The scanner uses the standard TLS flags for the handshake.
//
// The --ldaps flag tells the scanner to wrap the entire connection in a TLS
// session. --ldaps does not change the default port number from 389, so it
// should usually be coupled with e.g. --port 636 (the IANA "ldaps" port).
//
// The scanner never binds, so it only sees what the server shows anonymous
// clients.
//
// The output contains the root DSE attributes the server returned, the
// server's response to StartTLS, and if StartTLS was negotiated or --ldaps was
// set, the standard TLS logs.
//
// With --sslv2, after the server accepts StartTLS the scanner sends an SSL 2.0 CLIENT-HELLO
// (lib/sslv2) instead of the TLS handshake and stops after the reply; the
// outcome goes to the sslv2 field and is the scan status.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/sslv2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// RootDSE is the outcome of the root DSE read.
	RootDSE *SearchResult `json:"root_dse,omitempty"`

	// StartTLS is the server's response to the StartTLS request, if it is sent.
	StartTLS *ExtendedResponse `json:"starttls,omitempty"`

	// NoticeOfDisconnection is the unsolicited notification a server sends
	// right before closing the connection (RFC 4511, Section 4.4.1), if any.
	NoticeOfDisconnection *ExtendedResponse `json:"notice_of_disconnection,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTLS
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if StartTLS is sent or if --ldaps is used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`

	// SSLv2 is the reply to the SSL 2.0 CLIENT-HELLO sent instead of the TLS
	// handshake, if --sslv2 is used.
	SSLv2 *sslv2.UpgradeResult `json:"sslv2,omitempty"`
}

// SearchResult is the outcome of the root DSE search.
type SearchResult struct {
	// ResultCode is the resultCode of the SearchResultDone; absent if the
	// search did not complete.
	ResultCode *int `json:"result_code,omitempty"`

	// ResultName is the name of ResultCode (RFC 4511, Section 4.1.9).
	ResultName string `json:"result_name,omitempty"`

	// DiagnosticMessage is the diagnosticMessage of the SearchResultDone.
	DiagnosticMessage string `json:"diagnostic_message,omitempty"`

	// Attributes are the attributes of the root DSE entry, as the server sent them.
	Attributes []Attribute `json:"attributes,omitempty"`

	// Raw is the hex encoding of the messages read for the search (truncated).
	Raw string `json:"raw,omitempty"`
}

// ExtendedResponse is an ExtendedResponse from the server (RFC 4511, Section 4.12).
type ExtendedResponse struct {
	// ResultCode is the resultCode; absent if the response did not parse.
	ResultCode *int `json:"result_code,omitempty"`

	// ResultName is the name of ResultCode (RFC 4511, Section 4.1.9).
	ResultName string `json:"result_name,omitempty"`

	// MatchedDN is the matchedDN of the response.
	MatchedDN string `json:"matched_dn,omitempty"`

	// DiagnosticMessage is the diagnosticMessage of the response.
	DiagnosticMessage string `json:"diagnostic_message,omitempty"`

	// ResponseName is the responseName of the response, if present.
	ResponseName string `json:"response_name,omitempty"`

	// Raw is the hex encoding of the response as read from the wire.
	Raw string `json:"raw,omitempty"`
}

// Flags holds the command-line configuration for the LDAP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendSTARTTLSOverride indicates that the client should send the StartTLS request, regardless of if the server advertises it
	SendSTARTTLSOverride bool `long:"send-starttls-override" description:"Send the StartTLS request regardless of if the server advertises it in the root DSE"`

	// LDAPSecure indicates that the entire transaction should be wrapped in a TLS session.
	LDAPSecure bool `long:"ldaps" description:"Perform a TLS handshake immediately upon connecting."`

	// SSLv2 sends an SSL 2.0 CLIENT-HELLO instead of the TLS handshake after the upgrade.
	SSLv2 bool `long:"sslv2" description:"After the server accepts StartTLS, send an SSL 2.0 CLIENT-HELLO instead of the TLS handshake and stop after its reply"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("ldap", "Lightweight Directory Access Protocol (LDAP)",
		"Read the root DSE of an LDAP server, optionally over TLS. If the server advertises the StartTLS extended operation, "+
			"we'll send StartTLS and negotiate a TLS connection. "+
			"This can be overridden with the --send-starttls-override flag.", 389)
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
	if flags.SendSTARTTLSOverride && flags.LDAPSecure {
		return errors.New("cannot use --ldaps and --send-starttls-override at the same time")
	}
	if flags.SSLv2 && flags.LDAPSecure {
		return errors.New("cannot use --ldaps and --sslv2 at the same time")
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

// Message IDs of the requests the scanner sends.
const (
	rootDSEMessageID  = 1
	startTLSMessageID = 2
)

// maxSearchMessages bounds the number of messages read for the root DSE
// search, which has a single entry.
const maxSearchMessages = 16

// supportsSTARTTLS reports whether the root DSE lists the StartTLS extended
// operation in supportedExtension (RFC 4511, Section 4.12).
func supportsSTARTTLS(rootDSE *SearchResult) bool {
	if rootDSE == nil {
		return false
	}
	for _, attribute := range rootDSE.Attributes {
		if !strings.EqualFold(attribute.Name, "supportedExtension") {
			continue
		}
		for _, value := range attribute.Values {
			if value == startTLSOID {
				return true
			}
		}
	}
	return false
}

// isNoticeOfDisconnection reports whether msg is the unsolicited Notice of
// Disconnection, the only message with messageID 0 (RFC 4511, Section 4.1.1.1).
func isNoticeOfDisconnection(msg *Message) bool {
	return msg.ID == 0 && msg.Op == tagExtendedResponse
}

// parseExtendedResponse parses the content of an ExtendedResponse.
func parseExtendedResponse(content []byte, raw []byte) (*ExtendedResponse, error) {
	response := &ExtendedResponse{Raw: hexRaw(raw, maxRawSize)}
	result, rest, err := parseLDAPResult(content)
	if err != nil {
		return response, err
	}
	response.ResultCode = &result.ResultCode
	response.ResultName = resultName(result.ResultCode)
	response.MatchedDN = result.MatchedDN
	response.DiagnosticMessage = result.DiagnosticMessage
	response.ResponseName, err = extendedResponseName(rest)
	return response, err
}

// readRootDSE reads the responses to the root DSE search until its
// SearchResultDone. It returns the outcome so far even on error, unless not
// even the first message was LDAP, and the Notice of Disconnection if the
// server sent one instead.
func readRootDSE(conn *Connection) (*SearchResult, *ExtendedResponse, error) {
	rootDSE := &SearchResult{}
	var raw []byte
	for i := 0; i < maxSearchMessages; i++ {
		msg, msgRaw, err := conn.ReadMessage()
		raw = append(raw, msgRaw...)
		rootDSE.Raw = hexRaw(raw, maxRawSize)
		if err != nil {
			if i == 0 {
				return nil, nil, err
			}
			return rootDSE, nil, err
		}
		if isNoticeOfDisconnection(msg) {
			notice, err := parseExtendedResponse(msg.Content, msgRaw)
			return rootDSE, notice, err
		}
		if msg.ID != rootDSEMessageID {
			return rootDSE, nil, protocolError("messageID %d in reply to messageID %d", msg.ID, rootDSEMessageID)
		}
		switch msg.Op {
		case tagSearchResultEntry:
			attributes, err := parseSearchResultEntry(msg.Content)
			if err != nil {
				return rootDSE, nil, err
			}
			rootDSE.Attributes = append(rootDSE.Attributes, attributes...)
		case tagSearchResultReference:
			// A continuation reference carries no root DSE attributes.
		case tagSearchResultDone:
			result, _, err := parseLDAPResult(msg.Content)
			if err != nil {
				return rootDSE, nil, err
			}
			rootDSE.ResultCode = &result.ResultCode
			rootDSE.ResultName = resultName(result.ResultCode)
			rootDSE.DiagnosticMessage = result.DiagnosticMessage
			return rootDSE, nil, nil
		default:
			return rootDSE, nil, protocolError("protocolOp 0x%02x in reply to a SearchRequest", msg.Op)
		}
	}
	return rootDSE, nil, protocolError("no SearchResultDone after %d messages", maxSearchMessages)
}

// Scan performs the LDAP scan.
//  1. Open a TCP connection to the target port (default 389).
//  2. If --ldaps is set, perform a TLS handshake.
//  3. Read the root DSE.
//  4. If the server advertises StartTLS (or --send-starttls-override is set),
//     send the StartTLS request, read the result, negotiate a TLS connection.
//  5. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. LDAP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}

	if scanner.config.LDAPSecure {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. LDAP with LDAPSecure requires a TLS wrapper")
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
	ldapConn := Connection{Conn: conn}
	if err = ldapConn.SendMessage(rootDSERequest(rootDSEMessageID)); err != nil {
		if !scanner.config.LDAPSecure {
			result = nil
		}
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send root DSE request to %s: %w", target.String(), err)
	}
	rootDSE, notice, err := readRootDSE(&ldapConn)
	if rootDSE == nil {
		// Quit early if we didn't get a valid response
		if !scanner.config.LDAPSecure {
			result = nil
		}
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read root DSE from %s: %w", target.String(), err)
	}
	result.RootDSE = rootDSE
	result.NoticeOfDisconnection = notice
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read root DSE from %s: %w", target.String(), err)
	}
	if notice != nil {
		sr := zgrab2.SCAN_APPLICATION_ERROR
		if scanner.config.LDAPSecure {
			sr = zgrab2.SCAN_POST_TLS_APPLICATION_ERROR
		}
		return sr, result, fmt.Errorf("LDAP server sent a Notice of Disconnection to %s", target.String())
	}
	shouldSendSTARTTLS := scanner.config.SendSTARTTLSOverride || supportsSTARTTLS(rootDSE)
	// If the server supports StartTLS or user requests StartTLS, and we haven't already negotiated a TLS connection
	if shouldSendSTARTTLS && !scanner.config.LDAPSecure {
		if err := ldapConn.SendMessage(startTLSRequest(startTLSMessageID)); err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send StartTLS request: %w", err)
		}
		msg, raw, err := ldapConn.ReadMessage()
		if err != nil {
			if len(raw) > 0 {
				result.StartTLS = &ExtendedResponse{Raw: hexRaw(raw, maxRawSize)}
			}
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read StartTLS response: %w", err)
		}
		response, err := parseExtendedResponse(msg.Content, raw)
		if isNoticeOfDisconnection(msg) {
			result.NoticeOfDisconnection = response
			if err != nil {
				return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not parse Notice of Disconnection: %w", err)
			}
			return zgrab2.SCAN_APPLICATION_ERROR, result, errors.New("LDAP server sent a Notice of Disconnection in reply to StartTLS")
		}
		result.StartTLS = response
		if msg.ID != startTLSMessageID || msg.Op != tagExtendedResponse {
			result.StartTLS = &ExtendedResponse{Raw: hexRaw(raw, maxRawSize)}
			return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("protocolOp 0x%02x with messageID %d in reply to StartTLS", msg.Op, msg.ID)
		}
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not parse StartTLS response: %w", err)
		}
		if *response.ResultCode != resultSuccess {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("LDAP result %d (%s) returned from StartTLS request: %s", *response.ResultCode, response.ResultName, response.DiagnosticMessage)
		}
		if scanner.config.SSLv2 {
			var status zgrab2.ScanStatus
			status, result.SSLv2, err = sslv2.ProbeUpgrade(ldapConn.Conn)
			return status, result, err
		}
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. LDAP with StartTLS requires a TLS wrapper")
		}
		tlsConn, err := tlsWrapper(ctx, target, ldapConn.Conn)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
