package nntp

import (
	"io"
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Every NNTP response starts with a three-digit status code (RFC 3977,
// Section 3.2). Most responses are a single CRLF-terminated line; some, like
// the 101 reply to CAPABILITIES, are followed by a multi-line data block that
// ends with a line holding a single "." (RFC 3977, Section 3.1.1).

// lineEndRegex matches once a complete line has been read; used for the
// greeting and the reply to STARTTLS, which are single-line responses.
var lineEndRegex = regexp.MustCompile(`\r\n$`)

// capabilitiesEndRegex matches once the server has finished answering
// CAPABILITIES: either a 101 status line followed by a data block terminated
// by CRLF "." CRLF (an empty list being just "." CRLF), or any other status
// line on its own (e.g. 500 from a server that predates CAPABILITIES). The
// text after the code is optional (RFC 3977, Section 9.4.1).
var capabilitiesEndRegex = regexp.MustCompile(`(?:^101(?: [^\r\n]*)?\r\n(?:[\s\S]*\r\n)?\.\r\n$)|(?:^(?:[02-9]\d\d|1[1-9]\d|10[02-9])[^\r\n]*\r\n$)`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the NNTP connection.
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
