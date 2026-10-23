package ldap

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/zmap/zgrab2"
)

// LDAP messages are BER-encoded (RFC 4511, Section 5.1) with only the definite
// form of length encoding. Real servers do not use the shortest encoding: Active
// Directory and 389 Directory Server send four-octet long-form lengths (0x84) on
// every element, so every element is parsed with nextTLV and minimal encoding is
// never required.

// BER tags used by the module (RFC 4511, Section 4 and Appendix B).
const (
	tagBoolean     byte = 0x01
	tagInteger     byte = 0x02
	tagOctetString byte = 0x04
	tagEnumerated  byte = 0x0a
	tagSequence    byte = 0x30
	tagSet         byte = 0x31

	tagSearchRequest         byte = 0x63 // [APPLICATION 3]
	tagSearchResultEntry     byte = 0x64 // [APPLICATION 4]
	tagSearchResultDone      byte = 0x65 // [APPLICATION 5]
	tagSearchResultReference byte = 0x73 // [APPLICATION 19]
	tagExtendedRequest       byte = 0x77 // [APPLICATION 23]
	tagExtendedResponse      byte = 0x78 // [APPLICATION 24]
	tagFilterPresent         byte = 0x87 // Filter present [7]
	tagExtendedRequestName   byte = 0x80 // ExtendedRequest requestName [0]
	tagExtendedResponseName  byte = 0x8a // ExtendedResponse responseName [10]
)

// berIndefiniteLength is the first length octet of the indefinite form;
// berHighTagNumber is the tag-number pattern of the high-tag-number form.
const (
	berIndefiniteLength byte = 0x80
	berHighTagNumber    byte = 0x1f
)

// startTLSOID is the requestName of the StartTLS extended operation
// (RFC 4511, Section 4.14.1).
const startTLSOID = "1.3.6.1.4.1.1466.20037"

// noticeOfDisconnectionOID is the responseName of the unsolicited Notice of
// Disconnection (RFC 4511, Section 4.4.1).
const noticeOfDisconnectionOID = "1.3.6.1.4.1.1466.20036"

// resultSuccess is the LDAPResult resultCode for success (RFC 4511, Section 4.1.9).
const resultSuccess = 0

// maxMessageSize bounds the size of a single LDAPMessage read from the server.
const maxMessageSize = 1 << 20

// maxRawSize bounds the hex-encoded raw output kept for a reply.
const maxRawSize = 4096

// resultNames maps LDAPResult resultCodes to their names (RFC 4511, Section 4.1.9).
var resultNames = map[int]string{
	0:  "success",
	1:  "operationsError",
	2:  "protocolError",
	3:  "timeLimitExceeded",
	4:  "sizeLimitExceeded",
	5:  "compareFalse",
	6:  "compareTrue",
	7:  "authMethodNotSupported",
	8:  "strongerAuthRequired",
	10: "referral",
	11: "adminLimitExceeded",
	12: "unavailableCriticalExtension",
	13: "confidentialityRequired",
	14: "saslBindInProgress",
	16: "noSuchAttribute",
	17: "undefinedAttributeType",
	18: "inappropriateMatching",
	19: "constraintViolation",
	20: "attributeOrValueExists",
	21: "invalidAttributeSyntax",
	32: "noSuchObject",
	33: "aliasProblem",
	34: "invalidDNSyntax",
	36: "aliasDereferencingProblem",
	48: "inappropriateAuthentication",
	49: "invalidCredentials",
	50: "insufficientAccessRights",
	51: "busy",
	52: "unavailable",
	53: "unwillingToPerform",
	54: "loopDetect",
	64: "namingViolation",
	65: "objectClassViolation",
	66: "notAllowedOnNonLeaf",
	67: "notAllowedOnRDN",
	68: "entryAlreadyExists",
	69: "objectClassModsProhibited",
	71: "affectsMultipleDSAs",
	80: "other",
}

// resultName returns the name of an LDAPResult resultCode, or "" if unknown.
func resultName(code int) string {
	return resultNames[code]
}

// protocolError returns a SCAN_PROTOCOL_ERROR for bytes that do not parse as
// an LDAPMessage.
func protocolError(format string, args ...any) error {
	return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("invalid LDAP message: "+format, args...))
}

// Message is a parsed LDAPMessage envelope (RFC 4511, Section 4.1.1):
// SEQUENCE { messageID, protocolOp, controls [0] OPTIONAL }.
type Message struct {
	// ID is the messageID; 0 is reserved for the Notice of Disconnection.
	ID int
	// Op is the tag of the protocolOp, which identifies the operation.
	Op byte
	// Content is the content of the protocolOp, without its tag and length.
	Content []byte
}

// LDAPResult is the result carried by most LDAP responses (RFC 4511, Section 4.1.9).
type LDAPResult struct {
	ResultCode        int
	MatchedDN         string
	DiagnosticMessage string
}

// Attribute is one attribute of an entry, with its values as the server sent them.
type Attribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Connection wraps the state and access to the LDAP connection.
type Connection struct {
	Conn net.Conn
}

// SendMessage writes an encoded LDAPMessage to the connection.
func (conn *Connection) SendMessage(msg []byte) error {
	_, err := conn.Conn.Write(msg)
	return err
}

// ReadMessage reads one LDAPMessage from the connection. It returns the bytes
// it read even on error, so a malformed reply can still be kept in the results.
func (conn *Connection) ReadMessage() (*Message, []byte, error) {
	raw := make([]byte, 0, 64)
	read := func(n int) error {
		buf := make([]byte, n)
		m, err := io.ReadFull(conn.Conn, buf)
		raw = append(raw, buf[:m]...)
		if err == io.ErrUnexpectedEOF {
			return protocolError("truncated message after %d bytes", len(raw))
		}
		return err
	}
	if err := read(2); err != nil {
		return nil, raw, err
	}
	if raw[0] != tagSequence {
		return nil, raw, protocolError("expected SEQUENCE, got 0x%02x", raw[0])
	}
	if raw[1]&0x80 != 0 && raw[1] != berIndefiniteLength && raw[1]&0x7f <= 4 {
		if err := read(int(raw[1] & 0x7f)); err != nil {
			return nil, raw, err
		}
	}
	length, _, err := berLength(raw[1:])
	if err != nil {
		return nil, raw, err
	}
	if err = read(length); err != nil {
		return nil, raw, err
	}
	msg, err := parseMessage(raw[len(raw)-length:])
	return msg, raw, err
}

// parseMessage parses the content of an LDAPMessage SEQUENCE. Controls after
// the protocolOp are ignored.
func parseMessage(body []byte) (*Message, error) {
	tag, idBytes, rest, err := nextTLV(body)
	if err != nil {
		return nil, err
	}
	if tag != tagInteger {
		return nil, protocolError("expected messageID INTEGER, got 0x%02x", tag)
	}
	id, err := parseInt(idBytes)
	if err != nil {
		return nil, err
	}
	op, content, _, err := nextTLV(rest)
	if err != nil {
		return nil, err
	}
	return &Message{ID: id, Op: op, Content: content}, nil
}

// berLength decodes the BER length that starts at b[0], returning it and the
// number of length octets. Lengths may use the long form with up to four
// octets, minimal or not; the indefinite form is rejected (RFC 4511, Section
// 5.1), and so is any length above maxMessageSize, which also keeps the
// result within an int on 32-bit platforms.
func berLength(b []byte) (length int, n int, err error) {
	if len(b) == 0 {
		return 0, 0, protocolError("missing length")
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1, nil
	}
	if b[0] == berIndefiniteLength {
		return 0, 0, protocolError("indefinite length")
	}
	octets := int(b[0] & 0x7f)
	if octets > 4 {
		return 0, 0, protocolError("length of %d octets", octets)
	}
	if 1+octets > len(b) {
		return 0, 0, protocolError("truncated length")
	}
	var v uint64
	for _, c := range b[1 : 1+octets] {
		v = v<<8 | uint64(c)
	}
	if v > maxMessageSize {
		return 0, 0, protocolError("length of %d bytes exceeds the %d byte limit", v, maxMessageSize)
	}
	return int(v), 1 + octets, nil
}

// nextTLV splits the first BER element off b, returning its tag, its content
// and the bytes after it.
func nextTLV(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, protocolError("truncated element")
	}
	tag = b[0]
	if tag&berHighTagNumber == berHighTagNumber {
		return 0, nil, nil, protocolError("high tag number form in tag 0x%02x", tag)
	}
	length, n, err := berLength(b[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	i := 1 + n
	if length > len(b)-i {
		return 0, nil, nil, protocolError("element of %d bytes overruns its container", length)
	}
	return tag, b[i : i+length], b[i+length:], nil
}

// parseInt parses the content of a BER INTEGER or ENUMERATED that fits in 32
// bits; leading zero or sign octets (non-minimal encodings) are accepted.
func parseInt(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, protocolError("empty integer")
	}
	for len(b) > 1 && (b[0] == 0x00 && b[1]&0x80 == 0 || b[0] == 0xff && b[1]&0x80 != 0) {
		b = b[1:]
	}
	if len(b) > 4 {
		return 0, protocolError("integer of %d octets", len(b))
	}
	var v int32
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range b {
		v = v<<8 | int32(c)
	}
	return int(v), nil
}

// parseLDAPResult parses the LDAPResult at the start of the content of a
// response and returns the elements after it (e.g. referral, or the
// responseName of an ExtendedResponse).
func parseLDAPResult(content []byte) (*LDAPResult, []byte, error) {
	tag, code, rest, err := nextTLV(content)
	if err != nil {
		return nil, nil, err
	}
	if tag != tagEnumerated {
		return nil, nil, protocolError("expected resultCode ENUMERATED, got 0x%02x", tag)
	}
	result := &LDAPResult{}
	if result.ResultCode, err = parseInt(code); err != nil {
		return nil, nil, err
	}
	tag, matchedDN, rest, err := nextTLV(rest)
	if err != nil {
		return nil, nil, err
	}
	if tag != tagOctetString {
		return nil, nil, protocolError("expected matchedDN OCTET STRING, got 0x%02x", tag)
	}
	tag, diagnosticMessage, rest, err := nextTLV(rest)
	if err != nil {
		return nil, nil, err
	}
	if tag != tagOctetString {
		return nil, nil, protocolError("expected diagnosticMessage OCTET STRING, got 0x%02x", tag)
	}
	result.MatchedDN = string(matchedDN)
	result.DiagnosticMessage = string(diagnosticMessage)
	return result, rest, nil
}

// extendedResponseName returns the responseName [10] among the elements that
// follow the LDAPResult of an ExtendedResponse, or "" if it is absent.
func extendedResponseName(rest []byte) (string, error) {
	for len(rest) > 0 {
		tag, content, next, err := nextTLV(rest)
		if err != nil {
			return "", err
		}
		if tag == tagExtendedResponseName {
			return string(content), nil
		}
		rest = next
	}
	return "", nil
}

// parseSearchResultEntry parses the content of a SearchResultEntry:
// SEQUENCE { objectName, attributes PartialAttributeList }. Values are kept as
// the server sent them; they are OCTET STRINGs and may not be valid UTF-8.
func parseSearchResultEntry(content []byte) ([]Attribute, error) {
	tag, _, rest, err := nextTLV(content)
	if err != nil {
		return nil, err
	}
	if tag != tagOctetString {
		return nil, protocolError("expected objectName OCTET STRING, got 0x%02x", tag)
	}
	tag, list, _, err := nextTLV(rest)
	if err != nil {
		return nil, err
	}
	if tag != tagSequence {
		return nil, protocolError("expected attributes SEQUENCE, got 0x%02x", tag)
	}
	var attributes []Attribute
	for len(list) > 0 {
		var partial []byte
		tag, partial, list, err = nextTLV(list)
		if err != nil {
			return nil, err
		}
		if tag != tagSequence {
			return nil, protocolError("expected PartialAttribute SEQUENCE, got 0x%02x", tag)
		}
		tag, name, rest, err := nextTLV(partial)
		if err != nil {
			return nil, err
		}
		if tag != tagOctetString {
			return nil, protocolError("expected attribute type OCTET STRING, got 0x%02x", tag)
		}
		tag, set, _, err := nextTLV(rest)
		if err != nil {
			return nil, err
		}
		if tag != tagSet {
			return nil, protocolError("expected attribute values SET, got 0x%02x", tag)
		}
		attribute := Attribute{Name: string(name), Values: []string{}}
		for len(set) > 0 {
			var value []byte
			tag, value, set, err = nextTLV(set)
			if err != nil {
				return nil, err
			}
			if tag != tagOctetString {
				return nil, protocolError("expected attribute value OCTET STRING, got 0x%02x", tag)
			}
			attribute.Values = append(attribute.Values, string(value))
		}
		attributes = append(attributes, attribute)
	}
	return attributes, nil
}

// tlv encodes a BER element with a definite length (short or long form).
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	if n < 0x80 {
		out = append(out, byte(n))
	} else {
		var lengthBytes []byte
		for ; n > 0; n >>= 8 {
			lengthBytes = append([]byte{byte(n)}, lengthBytes...)
		}
		out = append(out, 0x80|byte(len(lengthBytes)))
		out = append(out, lengthBytes...)
	}
	return append(out, content...)
}

// berInt encodes the content of a small non-negative INTEGER or ENUMERATED.
func berInt(v int) []byte {
	out := []byte{byte(v)}
	for v >>= 8; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	if out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}
	return out
}

// envelope wraps a protocolOp in an LDAPMessage with the given messageID.
func envelope(msgID int, protocolOp []byte) []byte {
	return tlv(tagSequence, append(tlv(tagInteger, berInt(msgID)), protocolOp...))
}

// rootDSEAttributes are requested by name, as operational attributes of the
// root DSE are only returned when requested (RFC 4512, Sections 3.4 and 5.1).
var rootDSEAttributes = []string{"supportedLDAPVersion", "supportedExtension", "vendorName", "vendorVersion"}

// rootDSERequest encodes a SearchRequest reading the root DSE (RFC 4512,
// Section 5.1): baseObject "", scope baseObject, derefAliases neverDerefAliases,
// no size or time limit, filter (objectClass=*) (RFC 4511, Section 4.5.1).
func rootDSERequest(msgID int) []byte {
	attributes := make([]byte, 0, 64)
	for _, attribute := range rootDSEAttributes {
		attributes = append(attributes, tlv(tagOctetString, []byte(attribute))...)
	}
	search := make([]byte, 0, 128)
	search = append(search, tlv(tagOctetString, nil)...)      // baseObject ""
	search = append(search, tlv(tagEnumerated, berInt(0))...) // scope baseObject
	search = append(search, tlv(tagEnumerated, berInt(0))...) // derefAliases neverDerefAliases
	search = append(search, tlv(tagInteger, berInt(0))...)    // sizeLimit
	search = append(search, tlv(tagInteger, berInt(0))...)    // timeLimit
	search = append(search, tlv(tagBoolean, []byte{0x00})...) // typesOnly FALSE
	search = append(search, tlv(tagFilterPresent, []byte("objectClass"))...)
	search = append(search, tlv(tagSequence, attributes)...)
	return envelope(msgID, tlv(tagSearchRequest, search))
}

// startTLSRequest encodes the StartTLS ExtendedRequest; its requestValue is
// always absent (RFC 4511, Section 4.14.1).
func startTLSRequest(msgID int) []byte {
	return envelope(msgID, tlv(tagExtendedRequest, tlv(tagExtendedRequestName, []byte(startTLSOID))))
}

// hexRaw hex-encodes raw output, truncated to limit hex characters.
func hexRaw(raw []byte, limit int) string {
	if len(raw) > limit/2 {
		raw = raw[:limit/2]
	}
	return hex.EncodeToString(raw)
}
