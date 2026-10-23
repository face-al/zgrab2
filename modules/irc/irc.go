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

// capLSEndRegex matches once the server has finished answering CAP LS: the
// last line read is the final CAP LS line, whose capability list is a ":"
// trailing parameter (a continuation line carries a "*" before it), an error
// numeric (4xx/5xx, e.g. 421 from a server without CAP support), or an ERROR
// message.
var capLSEndRegex = regexp.MustCompile(`(?:^|\n)(?::\S+ )?(?:CAP \S+ LS :[^\r\n]*|[45]\d\d [^\r\n]*|ERROR [^\r\n]*)\r\n$`)

// numericEndRegex matches once the last line read is a numeric reply or an
// ERROR message; used for the reply to STARTTLS, which is a numeric (670 or 691).
var numericEndRegex = regexp.MustCompile(`(?:^|\n)(?::\S+ )?(?:\d\d\d [^\r\n]*|ERROR [^\r\n]*)\r\n$`)

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
