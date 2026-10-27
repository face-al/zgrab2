package nbd

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/zmap/zgrab2"
)

// Magic numbers of the handshake phase (NBD protocol, "Handshake").
const (
	// nbdMagic ("NBDMAGIC", also INIT_PASSWD) starts every greeting.
	nbdMagic uint64 = 0x4e42444d41474943
	// optMagic ("IHAVEOPT") follows it in newstyle greetings and starts every option request.
	optMagic uint64 = 0x49484156454f5054
	// cliservMagic follows it in oldstyle greetings instead.
	cliservMagic uint64 = 0x00420281861253
	// replyMagic starts every option reply of fixed newstyle negotiation.
	replyMagic uint64 = 0x3e889045565a9
)

// Handshake flags sent by the server ("Handshake flags"); servers MUST NOT set any other.
const (
	flagFixedNewstyle uint16 = 1 << 0
	flagNoZeroes      uint16 = 1 << 1
)

// clientFlagFixedNewstyle (NBD_FLAG_C_FIXED_NEWSTYLE) is the only client flag
// the scanner sets ("Client flags"). NBD_FLAG_C_NO_ZEROES only matters for
// NBD_OPT_EXPORT_NAME, which the scanner never sends.
const clientFlagFixedNewstyle uint32 = 1 << 0

// Options the scanner sends ("Option types").
const (
	optAbort    uint32 = 2
	optStartTLS uint32 = 5
)

// Option reply types ("Option reply types"); error types have bit 31 set.
const (
	repAck   uint32 = 1
	repError uint32 = 1 << 31
)

// replyNames maps option reply types to their names.
var replyNames = map[uint32]string{
	repAck:        "NBD_REP_ACK",
	2:             "NBD_REP_SERVER",
	3:             "NBD_REP_INFO",
	4:             "NBD_REP_META_CONTEXT",
	repError + 1:  "NBD_REP_ERR_UNSUP",
	repError + 2:  "NBD_REP_ERR_POLICY",
	repError + 3:  "NBD_REP_ERR_INVALID",
	repError + 4:  "NBD_REP_ERR_PLATFORM",
	repError + 5:  "NBD_REP_ERR_TLS_REQD",
	repError + 6:  "NBD_REP_ERR_UNKNOWN",
	repError + 7:  "NBD_REP_ERR_SHUTDOWN",
	repError + 8:  "NBD_REP_ERR_BLOCK_SIZE_REQD",
	repError + 9:  "NBD_REP_ERR_TOO_BIG",
	repError + 10: "NBD_REP_ERR_EXT_HEADER_REQD",
}

// replyName returns the name of an option reply type, or "" if unknown.
func replyName(replyType uint32) string {
	return replyNames[replyType]
}

// Sizes of the fixed-length messages read from the server.
const (
	// greetingMagicsSize covers NBDMAGIC and the second magic.
	greetingMagicsSize = 16
	// handshakeFlagsSize is the size of the newstyle handshake flags.
	handshakeFlagsSize = 2
	// replyHeaderSize covers the reply magic, option, reply type and length.
	replyHeaderSize = 20
)

// maxReplyData bounds the data read after an option reply header. Real
// servers cap their error messages at 4096 bytes (qemu's NBD_MAX_STRING_SIZE).
const maxReplyData = 4096

// protocolError returns a SCAN_PROTOCOL_ERROR for bytes that do not follow
// the NBD handshake.
func protocolError(format string, args ...any) error {
	return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("invalid NBD message: "+format, args...))
}

// OptionReply is the server's reply to an option request.
type OptionReply struct {
	// Option is the option the reply is for.
	Option uint32 `json:"option"`

	// ReplyType is the reply type, e.g. 1 for NBD_REP_ACK.
	ReplyType uint32 `json:"reply_type"`

	// ReplyName is the name of ReplyType, if known.
	ReplyName string `json:"reply_name,omitempty"`

	// Message is the data of an error reply, an error message for the user,
	// truncated to 4096 bytes.
	Message string `json:"message,omitempty"`

	// Raw is the hex encoding of the reply as read from the wire, with its
	// data truncated to 4096 bytes.
	Raw string `json:"raw,omitempty"`

	// length is the length of the reply's data, as the header gives it.
	length uint32
}

// Connection wraps the state and access to the NBD connection.
type Connection struct {
	Conn net.Conn
}

// read appends exactly n bytes from the connection to raw. A message cut short
// is a protocol error; a connection closed before its first byte is io.EOF.
func (conn *Connection) read(raw []byte, n int) ([]byte, error) {
	buf := make([]byte, n)
	m, err := io.ReadFull(conn.Conn, buf)
	raw = append(raw, buf[:m]...)
	if len(raw) > 0 && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
		return raw, protocolError("truncated message after %d bytes", len(raw))
	}
	return raw, err
}

// ReadGreeting reads the server's greeting: NBDMAGIC, then IHAVEOPT and the
// 16-bit handshake flags (newstyle), or cliserv_magic (oldstyle, whose export
// size and flags are not read). It returns the bytes it read even on error.
func (conn *Connection) ReadGreeting() ([]byte, error) {
	raw, err := conn.read(nil, greetingMagicsSize)
	if err != nil {
		return raw, err
	}
	if binary.BigEndian.Uint64(raw[:8]) != nbdMagic {
		return raw, protocolError("expected NBDMAGIC, got %x", raw[:8])
	}
	switch binary.BigEndian.Uint64(raw[8:16]) {
	case cliservMagic:
		return raw, nil
	case optMagic:
		return conn.read(raw, handshakeFlagsSize)
	}
	return raw, protocolError("expected IHAVEOPT or cliserv_magic, got %x", raw[8:16])
}

// optionRequest encodes an option request without data: IHAVEOPT, the
// option, and a zero length.
func optionRequest(option uint32) []byte {
	b := binary.BigEndian.AppendUint64(nil, optMagic)
	b = binary.BigEndian.AppendUint32(b, option)
	return binary.BigEndian.AppendUint32(b, 0)
}

// startTLSRequest is the client flags followed by NBD_OPT_STARTTLS, sent in
// one write, as TLS-Attacker does.
func startTLSRequest() []byte {
	return append(binary.BigEndian.AppendUint32(nil, clientFlagFixedNewstyle), optionRequest(optStartTLS)...)
}

// Send writes b to the connection.
func (conn *Connection) Send(b []byte) error {
	_, err := conn.Conn.Write(b)
	return err
}

// ReadOptionReply reads the reply to option. A reply with another magic or
// for another option is a protocol error. It returns the reply read so far
// even on error, or nil if nothing was read.
func (conn *Connection) ReadOptionReply(option uint32) (*OptionReply, error) {
	raw, err := conn.read(nil, replyHeaderSize)
	if len(raw) == 0 {
		return nil, err
	}
	reply := &OptionReply{Raw: hex.EncodeToString(raw)}
	if err != nil {
		return reply, err
	}
	if magic := binary.BigEndian.Uint64(raw[:8]); magic != replyMagic {
		return reply, protocolError("expected reply magic, got %x", raw[:8])
	}
	reply.Option = binary.BigEndian.Uint32(raw[8:12])
	reply.ReplyType = binary.BigEndian.Uint32(raw[12:16])
	reply.ReplyName = replyName(reply.ReplyType)
	if reply.Option != option {
		return reply, protocolError("reply for option %d to option %d", reply.Option, option)
	}
	reply.length = binary.BigEndian.Uint32(raw[16:20])
	if reply.length == 0 {
		return reply, nil
	}
	raw, err = conn.read(raw, int(min(reply.length, maxReplyData)))
	reply.Raw = hex.EncodeToString(raw)
	if err != nil {
		return reply, err
	}
	if reply.ReplyType&repError != 0 {
		reply.Message = string(raw[replyHeaderSize:])
	}
	return reply, nil
}
