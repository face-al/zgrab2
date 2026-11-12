package irc

import (
	"io"
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// IRC messages are CRLF-terminated lines of the form
// [":" prefix SPACE] command [params] (RFC 2812, Section 2.3.1), where command
// is either a word or a three-digit numeric reply (RFC 2812, Section 2.4).
// Some servers end lines with a bare LF; like TLS-Attacker, accept both.

// IRC has no end-of-reply marker, and a server may send unrelated lines (e.g.
// hostname lookup NOTICEs) at any time, also after its reply. So the end
// regexes match the reply's final line anywhere in the buffer, not only as the
// last line read, like TLS-Attacker's line-by-line matching.

// capLSEndRegex matches once the server has finished answering CAP LS: the
// final CAP LS line, whose capability list is a ":" trailing parameter (a
// continuation line carries a "*" before it), an error numeric (4xx/5xx, e.g.
// 421 from a server without CAP support), or an ERROR message.
var capLSEndRegex = regexp.MustCompile(`(?m)^(?::\S+ )?(?:CAP \S+ LS :|[45]\d\d |ERROR )[^\r\n]*\r?\n`)

// startTLSEndRegex matches once the server has answered STARTTLS: 670
// (RPL_STARTTLS), 691 (ERR_STARTTLS), another error numeric (4xx/5xx), or an
// ERROR message. Other numerics (e.g. 020) do not end the reply. The code is
// captured.
var startTLSEndRegex = regexp.MustCompile(`(?m)^(?::\S+ )?(?:(670|691|[45]\d\d) |ERROR )[^\r\n]*\r?\n`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the IRC connection.
type Connection struct {
	Conn net.Conn
}

// ReadResponse reads from the connection until it matches endRegex.
func (conn *Connection) ReadResponse(endRegex *regexp.Regexp) (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, endRegex)
	if err != nil && err != io.EOF && !zgrab2.IsTimeoutError(err) {
		return "", err
	}
	return string(ret[:n]), nil
}

// SendCommand sends a command, followed by a CRLF, then waits for / reads the
// server's response up to endRegex.
func (conn *Connection) SendCommand(cmd string, endRegex *regexp.Regexp) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse(endRegex)
}
