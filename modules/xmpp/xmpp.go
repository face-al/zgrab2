package xmpp

import (
	"io"
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// An XMPP stream is one XML document sent in pieces (RFC 6120, Section 4);
// the scanner reads until the element it waits for is complete, matching
// the text with the same patterns TLS-Attacker uses. Like TLS-Attacker, they
// require the "stream" prefix for the stream namespace, which every server
// uses although RFC 6120, Section 4.8.5 allows any prefix.

// openingEndRegex matches once the reply to the opening stream header holds
// the stream features (TLS-Attacker's FEATURES_REGEX: empty, or the whole
// element, not up to the first "/>" inside it), a stream error, or the end of
// the stream (RFC 6120, Sections 4.3.2, 4.9.1.2 and 4.4).
var openingEndRegex = regexp.MustCompile(`(?s)<stream:features(?:\s*/>|\b.*?</stream:features>)|</stream:error>|<stream:error\b[^>]*/>|</stream:stream>`)

// upgradeEndRegex matches once the reply to the STARTTLS command holds
// <proceed/> (TLS-Attacker's PROCEED_REGEX), a whole <failure/>, a stream
// error, or the end of the stream (RFC 6120, Sections 5.4.2.2 and 5.4.2.3).
var upgradeEndRegex = regexp.MustCompile(`(?s)<proceed\b[^>]*?(?:/>|>\s*</proceed>)|<failure\b[^>]*?(?:/>|>.*?</failure>)|</stream:error>|<stream:error\b[^>]*/>|</stream:stream>`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the XMPP connection.
type Connection struct {
	Conn net.Conn
}

// ReadResponse reads from the connection until it matches endRegex. A
// timeout or EOF after some data returns that data, to be judged by the
// caller; without any data it is returned as the error.
func (conn *Connection) ReadResponse(endRegex *regexp.Regexp) (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, endRegex)
	if err != nil && (n == 0 || (err != io.EOF && !zgrab2.IsTimeoutError(err))) {
		return "", err
	}
	return string(ret[:n]), nil
}

// SendCommand sends an XML fragment as is, then waits for / reads the
// server's response up to endRegex.
func (conn *Connection) SendCommand(cmd string, endRegex *regexp.Regexp) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd)); err != nil {
		return "", err
	}
	return conn.ReadResponse(endRegex)
}
