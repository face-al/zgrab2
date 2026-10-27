package lmtp

import (
	"io"
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Every LMTP reply is SMTP's (RFC 2033, Section 4): one or more lines, each
// starting with the same three-digit code, where every line but the last has
// a "-" after the code and the last has a space and text or nothing at all
// (RFC 5321, Section 4.2).

// replyEndRegex matches once a line has been read that is not a continuation
// line (a code followed by "-"): the last line of a reply, with or without
// text. Any other line also ends the reply, so a non-LMTP service is reported
// at once instead of after the read timeout; getLMTPCode then rejects it.
var replyEndRegex = regexp.MustCompile(`(?:^|\r\n)(?:[^\r\n]{0,3}|[^\d\r\n][^\r\n]*|\d[^\d\r\n][^\r\n]*|\d\d[^\d\r\n][^\r\n]*|\d\d\d[^-\r\n][^\r\n]*)\r\n$`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the LMTP connection.
type Connection struct {
	Conn net.Conn
}

// ReadResponse reads from the connection until it matches replyEndRegex.
func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, replyEndRegex)
	if err != nil && err != io.EOF && !zgrab2.IsTimeoutError(err) {
		return "", err
	}
	return string(ret[:n]), nil
}

// SendCommand sends a command, followed by a CRLF, then waits for / reads the
// server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}
