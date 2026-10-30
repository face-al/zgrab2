package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

// Upgrade to TLS within HTTP/1.1 (RFC 2817), --starttls.
//
// The client asks with the mandatory upgrade (RFC 2817, Section 3.2): an
// OPTIONS * carrying "Upgrade: TLS/1.0" and, as every Upgrade must,
// "Connection: Upgrade" (RFC 9110, Section 7.8). A server that agrees answers
// "101 Switching Protocols" and starts TLS right after the empty line ending
// it; over TLS it then answers the OPTIONS (RFC 2817, Section 3.3). Any other
// status refuses, e.g. 200 from a server that ignores the Upgrade (RFC 2817,
// Section 3.1) or 426 asking for another token (Section 4.2); TLS-Attacker
// does not retry those either.
//
// The request and both reply patterns are TLS-Attacker's (StarttlsType.HTTP),
// so the two tools count the same hosts as upgrading. One deviation: an IPv6
// Host is bracketed, as RFC 9110, Section 7.2 requires; TLS-Attacker sends it
// bare, which strict servers answer with 400. Like TLS-Attacker, the Host has
// no port, also on non-default ports, and no ALPN is offered by default.

// upgradeRequest is TLS-Attacker's OPTIONS_UPGRADE; %s is the Host.
const upgradeRequest = "OPTIONS * HTTP/1.1\r\nHost: %s\r\nUpgrade: TLS/1.0\r\nConnection: Upgrade\r\n\r\n"

// upgradeReadSize bounds the plaintext reply head.
const upgradeReadSize = 0x10000

// maxInterimResponses bounds the 1xx responses skipped over TLS before the
// final response to the OPTIONS (RFC 9110, Section 15.2).
const maxInterimResponses = 8

const (
	// switchingPattern is TLS-Attacker's SWITCHING_PROTOCOLS_REGEX: the whole
	// 101 head, so none of it is left for TLS; bare LFs tolerated.
	switchingPattern = `HTTP/1\.\d 101[ \r][\s\S]*?\r?\n\r?\n`

	// refusalPattern is TLS-Attacker's ERROR_REGEX with its (?!101) lookahead
	// spelled out for RE2: any other status, or a first byte that cannot
	// start a status line. It needs all three digits, so "HTTP/1.1 10" does
	// not end a 101 early, and it matches on the status line alone.
	refusalPattern = `HTTP/\d(?:\.\d)? (?:[02-9]\d\d|1[1-9]\d|10[02-9])|[^H]`
)

var (
	switchingRegex = regexp.MustCompile(`\A(?:` + switchingPattern + `)`)
	refusalRegex   = regexp.MustCompile(`\A(?:` + refusalPattern + `)`)

	// upgradeEndRegex ends the read as soon as either pattern matches, as
	// TLS-Attacker checks both on every chunk.
	upgradeEndRegex = regexp.MustCompile(`\A(?:` + switchingPattern + `|` + refusalPattern + `)`)
)

// validateStartTLS rejects the flags that --starttls would otherwise ignore:
// it sends one fixed request on one plaintext connection.
func (flags Flags) validateStartTLS() error {
	switch {
	case flags.UseHTTPS, flags.RetryHTTPS, flags.FailHTTPToHTTPS:
		return errors.New("--starttls upgrades a plaintext connection; it cannot be used with --use-https, --retry-https or --fail-http-to-https")
	case flags.NoHTTP11:
		return errors.New("--starttls upgrades HTTP/1.1; it cannot be used with --no-http1.1")
	case flags.MaxRedirects != 0:
		return errors.New("--starttls does not follow redirects; it cannot be used with --max-redirects")
	case flags.Method != "GET" || flags.Endpoint != "/":
		return errors.New("--starttls always sends OPTIONS *; it cannot be used with --method or --endpoint")
	case flags.RequestBody != "" || flags.RequestBodyHex != "":
		return errors.New("--starttls sends no body; it cannot be used with --request-body or --request-body-hex")
	case flags.CustomHeadersNames != "" || flags.CustomHeadersValues != "" || flags.SkipHost:
		return errors.New("--starttls sends fixed headers; it cannot be used with --custom-headers-names, --custom-headers-values or --skip-host")
	case flags.RedirectsSucceed || flags.RawHeaders:
		return errors.New("--starttls follows no redirects and keeps no raw headers; it cannot be used with --redirects-succeed or --raw-headers")
	case slices.Contains(strings.Split(flags.NextProtos, ","), "h2"):
		return errors.New("--starttls upgrades to HTTP/1.1; --next-protos cannot offer h2")
	}
	return nil
}

// upgradeHost is the Host of the upgrading request: the target's name, else
// its IP address, without port.
func upgradeHost(target *zgrab2.ScanTarget) string {
	host := target.Domain
	if host == "" {
		host = target.IP.String()
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// scanStartTLS asks for the upgrade, negotiates TLS on 101 and reads the
// response to the OPTIONS over TLS into Results.Response.
func (scanner *Scanner) scanStartTLS(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.L4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &Results{}

	host := upgradeHost(target)
	if _, err = fmt.Fprintf(conn, upgradeRequest, host); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send upgrade request: %w", err)
	}
	buf := make([]byte, upgradeReadSize)
	n, err := zgrab2.ReadUntilRegex(conn, buf, upgradeEndRegex)
	reply := string(buf[:n])
	if n > 0 {
		result.StartTLS = reply
	}
	switch {
	case switchingRegex.MatchString(reply):
		// Upgrade accepted. Bytes the server sent past the head are kept in
		// StartTLS only; TLS starts after them, as in TLS-Attacker.
	case refusalRegex.MatchString(reply) && reply[0] == 'H':
		return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("upgrade refused: %s", firstLine(reply))
	case refusalRegex.MatchString(reply):
		return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("invalid response for HTTP: %q", firstLine(reply))
	case errors.Is(err, io.EOF):
		return zgrab2.SCAN_CONNECTION_CLOSED, result, fmt.Errorf("connection closed during upgrade reply: %w", err)
	case errors.Is(err, zgrab2.ErrInsufficientBuffer):
		return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("no complete upgrade reply within %d bytes", upgradeReadSize)
	default:
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read upgrade reply: %w", err)
	}

	tlsConn, err := dialGroup.TLSWrapper(ctx, target, conn)
	if tlsConn != nil {
		result.TLSLog = tlsConn.GetLog()
	}
	if err != nil {
		return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("could not complete TLS handshake: %w", err)
	}

	req := &http.Request{
		Method:     "OPTIONS",
		URL:        &url.URL{Opaque: "*"},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Upgrade": {"TLS/1.0"}, "Connection": {"Upgrade"}},
		Host:       host,
	}
	br := bufio.NewReader(tlsConn)
	var resp *http.Response
	for i := 0; ; i++ {
		resp, err = http.ReadResponse(br, req)
		if err != nil {
			return zgrab2.SCAN_POST_TLS_APPLICATION_ERROR, result, fmt.Errorf("could not read response over TLS: %w", err)
		}
		if resp.StatusCode >= 200 || i == maxInterimResponses {
			break
		}
		resp.Body.Close()
	}
	// Not closed: Close would drain the body past --max-size; the deferred
	// close of the connection ends it.
	result.Response = resp
	if resp.StatusCode < 200 {
		return zgrab2.SCAN_POST_TLS_APPLICATION_ERROR, result, fmt.Errorf("no final response over TLS after %d interim responses", maxInterimResponses)
	}
	bodyBuf, bodyText, readLen, scanErr := scanner.readBody(resp)
	if scanErr != nil {
		return scanErr.Unpack(result)
	}
	scanner.setBody(resp, bodyBuf, bodyText, readLen)
	return zgrab2.SCAN_SUCCESS, result, nil
}

// firstLine returns the first line of reply, for error messages.
func firstLine(reply string) string {
	line, _, _ := strings.Cut(reply, "\n")
	return strings.TrimRight(line, "\r")
}
