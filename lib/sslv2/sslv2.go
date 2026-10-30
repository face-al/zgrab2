// Package sslv2 sends an SSL 2.0 CLIENT-HELLO and parses the server's
// SERVER-HELLO or ERROR (draft-hickman-netscape-ssl-00). It is shared by
// the sslv2 module (SSL 2.0 on connect) and the STARTTLS modules' --sslv2
// flag (SSL 2.0 after the application-layer upgrade).
//
// The CLIENT-HELLO (section 5.5.1) goes in a record with a 2-byte header
// (section 4.1): version 0x0002, all seven cipher kinds of Appendix C.4, no
// session identifier and a random 16-byte challenge. These are the bytes of
// TLS-Attacker's SSL2 ClientHello. One record and its message are read.
//
// A SERVER-HELLO (section 5.6.1) that answers a CLIENT-HELLO without a
// session identifier is a success: SESSION-ID-HIT 0, certificate type
// SSL_CT_X509_CERTIFICATE, version 0x0002, a certificate, a cipher spec list
// of whole specs, a connection identifier of 16 to 32 bytes, and lengths
// that add up to the record length. The certificate is also parsed as
// X.509; a parse failure is kept in the results and does not fail the scan.
//
// An ERROR message (section 5.7.1) with a known error code is an
// application error: the server speaks SSL 2.0 but refused the CLIENT-HELLO.
// A TLS record (e.g. the alert OpenSSL 1.1 and later send), any other
// message or record, or a record cut short is a protocol error. A connection
// closed without a reply, as SSL 3.0 and TLS servers without SSL 2.0 support
// usually do, is reported as connection-closed.
//
// The exchange stops after the SERVER-HELLO: no CLIENT-MASTER-KEY is sent,
// so no keys are exchanged and the server's SERVER-VERIFY is not checked.
// TLS-Attacker's SSL2 hello workflow likewise ends with the SERVER-HELLO.
package sslv2

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zgrab2"
)

// Message types (SSL 2.0, Appendix C.2).
const (
	msgError       byte = 0
	msgClientHello byte = 1
	msgServerHello byte = 4
)

// version is SSL_CLIENT_VERSION and SSL_SERVER_VERSION (Appendix C.1).
const version uint16 = 0x0002

// certificateTypeX509 is SSL_CT_X509_CERTIFICATE (Appendix C.5).
const certificateTypeX509 byte = 0x01

// Sizes and bounds of the messages (sections 5.5.1, 5.6.1, 5.7.1).
const (
	// challengeLength is the length of the CLIENT-HELLO challenge, 16 bytes
	// as in TLS-Attacker (the draft allows 16 to 32).
	challengeLength = 16
	// serverHelloHeaderLength is the length of the SERVER-HELLO fields
	// before the certificate.
	serverHelloHeaderLength = 11
	// errorLength is the length of an ERROR message.
	errorLength = 3
	// minConnectionIDLength and maxConnectionIDLength bound the length of
	// the SERVER-HELLO CONNECTION-ID ("between 16 and 32 bytes, inclusive").
	minConnectionIDLength = 16
	maxConnectionIDLength = 32
	// cipherSpecLength is the length of a CIPHER-KIND.
	cipherSpecLength = 3
)

// maxRawLength bounds the bytes kept in the results' raw field.
const maxRawLength = 4096

// Cipher kinds (Appendix C.4), in the order the CLIENT-HELLO offers them.
var cipherKinds = []struct {
	value [cipherSpecLength]byte
	name  string
}{
	{[3]byte{0x01, 0x00, 0x80}, "SSL_CK_RC4_128_WITH_MD5"},
	{[3]byte{0x02, 0x00, 0x80}, "SSL_CK_RC4_128_EXPORT40_WITH_MD5"},
	{[3]byte{0x03, 0x00, 0x80}, "SSL_CK_RC2_128_CBC_WITH_MD5"},
	{[3]byte{0x04, 0x00, 0x80}, "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5"},
	{[3]byte{0x05, 0x00, 0x80}, "SSL_CK_IDEA_128_CBC_WITH_MD5"},
	{[3]byte{0x06, 0x00, 0x40}, "SSL_CK_DES_64_CBC_WITH_MD5"},
	{[3]byte{0x07, 0x00, 0xc0}, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"},
}

// cipherKindName returns the name of a CIPHER-KIND, or its hex encoding if unknown.
func cipherKindName(kind []byte) string {
	for _, k := range cipherKinds {
		if string(k.value[:]) == string(kind) {
			return k.name
		}
	}
	return hex.EncodeToString(kind)
}

// Error codes of the ERROR message (Appendix C.3).
var errorNames = map[uint16]string{
	0x0001: "SSL_PE_NO_CIPHER",
	0x0002: "SSL_PE_NO_CERTIFICATE",
	0x0004: "SSL_PE_BAD_CERTIFICATE",
	0x0006: "SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE",
}

// ServerHello is the server's SERVER-HELLO message (section 5.6.1).
type ServerHello struct {
	// SessionIDHit is the SESSION-ID-HIT flag, always 0 since the
	// CLIENT-HELLO has no session identifier.
	SessionIDHit uint8 `json:"session_id_hit"`

	// CertificateType is the CERTIFICATE-TYPE, 1 for SSL_CT_X509_CERTIFICATE.
	CertificateType uint8 `json:"certificate_type"`

	// Version is the SERVER-VERSION, 2 for SSL 2.0.
	Version uint16 `json:"version"`

	// CipherSpecs are the names of the CIPHER-SPECS, or the hex encoding of
	// unknown ones.
	CipherSpecs []string `json:"cipher_specs"`

	// CipherSpecsRaw is the hex encoding of the CIPHER-SPECS-DATA.
	CipherSpecsRaw string `json:"cipher_specs_raw"`

	// ConnectionID is the hex encoding of the CONNECTION-ID-DATA.
	ConnectionID string `json:"connection_id"`

	// Certificate is the server's certificate.
	Certificate *Certificate `json:"certificate"`
}

// Certificate is the server's X.509 certificate, raw and parsed, like the
// tls module's server certificates.
type Certificate struct {
	// Raw is the DER encoding of the certificate.
	Raw []byte `json:"raw"`

	// Parsed is the parsed certificate, if it could be parsed.
	Parsed *x509.Certificate `json:"parsed,omitempty"`

	// ParseError is the error parsing the certificate, if any.
	ParseError string `json:"parse_error,omitempty"`
}

// Result is the outcome of one CLIENT-HELLO.
type Result struct {
	// ServerHello is the server's SERVER-HELLO.
	ServerHello *ServerHello `json:"server_hello,omitempty"`

	// Error is the server's ERROR message.
	Error *ErrorMessage `json:"error,omitempty"`

	// HeaderLength is the length of the reply's record header, 2 or 3.
	HeaderLength int `json:"header_len,omitempty"`

	// Raw is the hex encoding of the bytes read from the server, up to 4096.
	Raw string `json:"raw,omitempty"`
}

// Probe sends a CLIENT-HELLO on conn and reads the reply. The result is nil
// if nothing was read.
func Probe(conn net.Conn) (zgrab2.ScanStatus, *Result, error) {
	challenge, err := newChallenge()
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, fmt.Errorf("could not generate challenge: %w", err)
	}
	if _, err = conn.Write(clientHello(challenge)); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send CLIENT-HELLO: %w", err)
	}
	sslConn := Connection{Conn: conn}
	msg, headerLength, err := sslConn.ReadMessage()
	result := &Result{HeaderLength: headerLength}
	if raw := sslConn.Raw(); len(raw) > 0 {
		result.Raw = hex.EncodeToString(raw)
	}
	if err != nil {
		if result.Raw == "" {
			result = nil
		}
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read reply to CLIENT-HELLO: %w", err)
	}

	if msg[0] == msgError {
		result.Error, err = ParseError(msg)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("SSL 2.0 ERROR %s (0x%04x) returned from CLIENT-HELLO", result.Error.Name, result.Error.Code)
	}
	result.ServerHello, err = ParseServerHello(msg)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

// UpgradeResult is the outcome of a CLIENT-HELLO sent in place of the TLS
// handshake after an application-layer upgrade (STARTTLS). It is present
// whenever the CLIENT-HELLO was attempted, so a failure after the upgrade is
// told apart from one before it.
type UpgradeResult struct {
	// Status is the outcome of the CLIENT-HELLO; the module returns it as
	// its scan status.
	Status zgrab2.ScanStatus `json:"status"`

	*Result
}

// ProbeUpgrade runs Probe on conn, the upgraded connection of a STARTTLS
// module, and wraps its result for the module's sslv2 field.
func ProbeUpgrade(conn net.Conn) (zgrab2.ScanStatus, *UpgradeResult, error) {
	status, result, err := Probe(conn)
	return status, &UpgradeResult{Status: status, Result: result}, err
}

// ErrorMessage is the server's ERROR message (section 5.7.1).
type ErrorMessage struct {
	// Code is the ERROR-CODE.
	Code uint16 `json:"code"`

	// Name is the name of Code.
	Name string `json:"name"`
}

// protocolError returns a SCAN_PROTOCOL_ERROR for bytes that are not the
// expected SSL 2.0 record or message.
func protocolError(format string, args ...any) error {
	return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("invalid SSL 2.0 message: "+format, args...))
}

// clientHello encodes a CLIENT-HELLO record (sections 4.1 and 5.5.1) with
// a 2-byte header, version 0x0002, all seven cipher kinds, no session
// identifier and the given challenge, like TLS-Attacker's SSL2 ClientHello.
func clientHello(challenge []byte) []byte {
	body := []byte{msgClientHello}
	body = binary.BigEndian.AppendUint16(body, version)
	body = binary.BigEndian.AppendUint16(body, uint16(len(cipherKinds)*cipherSpecLength))
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(challenge)))
	for _, k := range cipherKinds {
		body = append(body, k.value[:]...)
	}
	body = append(body, challenge...)
	record := binary.BigEndian.AppendUint16(nil, 0x8000|uint16(len(body)))
	return append(record, body...)
}

// newChallenge returns a random CLIENT-HELLO challenge.
func newChallenge() ([]byte, error) {
	challenge := make([]byte, challengeLength)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

// Connection wraps the state and access to the SSL 2.0 connection.
type Connection struct {
	Conn net.Conn
	// raw holds the bytes read so far, up to maxRawLength.
	raw []byte
}

// Raw returns the bytes read so far, up to maxRawLength.
func (conn *Connection) Raw() []byte {
	return conn.raw
}

// read reads exactly n bytes. A connection closed before the first byte of
// the record is a SCAN_CONNECTION_CLOSED; a record cut short is a protocol
// error.
func (conn *Connection) read(n int) ([]byte, error) {
	buf := make([]byte, n)
	m, err := io.ReadFull(conn.Conn, buf)
	if room := maxRawLength - len(conn.raw); room > 0 {
		conn.raw = append(conn.raw, buf[:min(m, room)]...)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		if len(conn.raw) == 0 {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_CLOSED, errors.New("connection closed without a reply"))
		}
		return nil, protocolError("truncated record after %d bytes", len(conn.raw))
	}
	return buf, err
}

// isTLSRecordHeader reports whether b starts like a TLS alert or handshake
// record (type 0x15 or 0x16, version 0x03xx): a TLS server's reply to the
// CLIENT-HELLO.
func isTLSRecordHeader(b []byte) bool {
	return (b[0] == 0x15 || b[0] == 0x16) && b[1] == 0x03 && b[2] < 0x10
}

// readTLSRecord reads the rest of a TLS record whose first 3 bytes were
// read, up to maxRawLength, to keep it in the results.
func (conn *Connection) readTLSRecord() {
	rest, err := conn.read(2)
	if err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(rest))
	_, _ = conn.read(min(length, maxRawLength))
}

// ReadMessage reads one SSL 2.0 record (section 4.1) and returns its
// message and the length of the record header (2 or 3). A TLS record, a
// header not allowed for a record in the clear (section 4.1.1: no padding,
// no security escape), an empty record, or a message that is neither
// SERVER-HELLO nor ERROR is a protocol error. The message type is checked
// before the rest of the record is read, so that a reply of another
// protocol fails early.
func (conn *Connection) ReadMessage() ([]byte, int, error) {
	header, err := conn.read(2)
	if err != nil {
		return nil, 0, err
	}
	var length, headerLength int
	if header[0]&0x80 != 0 {
		headerLength = 2
		length = int(header[0]&0x7f)<<8 | int(header[1])
	} else {
		headerLength = 3
		padding, paddingErr := conn.read(1)
		if paddingErr != nil {
			return nil, 0, paddingErr
		}
		header = append(header, padding...)
		// TLS records have the MSB of the first byte clear too.
		if isTLSRecordHeader(header) {
			conn.readTLSRecord()
			return nil, 0, protocolError("TLS record %x in reply to the CLIENT-HELLO", header)
		}
		if header[0]&0x40 != 0 {
			return nil, 0, protocolError("security escape record header %x", header)
		}
		if header[2] != 0 {
			return nil, 0, protocolError("padding %d in a record sent in the clear", header[2])
		}
		length = int(header[0]&0x3f)<<8 | int(header[1])
	}
	if length == 0 {
		return nil, headerLength, protocolError("empty record")
	}
	msgType, err := conn.read(1)
	if err != nil {
		return nil, headerLength, err
	}
	switch {
	case msgType[0] == msgServerHello && length >= serverHelloHeaderLength:
	case msgType[0] == msgError && length == errorLength:
	default:
		return nil, headerLength, protocolError("message type %d in a record of %d bytes", msgType[0], length)
	}
	rest, err := conn.read(length - 1)
	if err != nil {
		return nil, headerLength, err
	}
	return append(msgType, rest...), headerLength, nil
}

// ParseError parses an ERROR message. An unknown error code is a protocol error.
func ParseError(msg []byte) (*ErrorMessage, error) {
	code := binary.BigEndian.Uint16(msg[1:3])
	name, ok := errorNames[code]
	if !ok {
		return nil, protocolError("unknown error code 0x%04x", code)
	}
	return &ErrorMessage{Code: code, Name: name}, nil
}

// ParseServerHello parses a SERVER-HELLO message and checks that it answers
// a CLIENT-HELLO without a session identifier: SESSION-ID-HIT 0, an X.509
// certificate, version 0x0002, a certificate, at least one cipher spec, a
// connection identifier of 16 to 32 bytes, and lengths that add up to the
// message length. A certificate that does not parse is kept raw with
// ParseError set; it does not fail the message.
func ParseServerHello(msg []byte) (*ServerHello, error) {
	hello := &ServerHello{
		SessionIDHit:    msg[1],
		CertificateType: msg[2],
		Version:         binary.BigEndian.Uint16(msg[3:5]),
	}
	certLength := int(binary.BigEndian.Uint16(msg[5:7]))
	specsLength := int(binary.BigEndian.Uint16(msg[7:9]))
	connIDLength := int(binary.BigEndian.Uint16(msg[9:11]))
	switch {
	case hello.SessionIDHit != 0:
		return nil, protocolError("SESSION-ID-HIT %d without a session identifier", hello.SessionIDHit)
	case hello.CertificateType != certificateTypeX509:
		return nil, protocolError("certificate type %d", hello.CertificateType)
	case hello.Version != version:
		return nil, protocolError("server version 0x%04x", hello.Version)
	case certLength == 0:
		return nil, protocolError("no certificate")
	// §5.5.1 requires a non-empty list only in the CLIENT-HELLO; a server
	// that answers with a certificate and no cipher spec still committed to
	// SSLv2 (TLS-Attacker's SSL2ServerHelloParser accepts it too).
	case specsLength%cipherSpecLength != 0:
		return nil, protocolError("cipher specs length %d", specsLength)
	case connIDLength < minConnectionIDLength || connIDLength > maxConnectionIDLength:
		return nil, protocolError("connection id length %d", connIDLength)
	case serverHelloHeaderLength+certLength+specsLength+connIDLength != len(msg):
		return nil, protocolError("lengths %d+%d+%d do not add up to message length %d", certLength, specsLength, connIDLength, len(msg)-serverHelloHeaderLength)
	}
	rest := msg[serverHelloHeaderLength:]
	cert := &Certificate{Raw: rest[:certLength]}
	if parsed, err := x509.ParseCertificate(cert.Raw); err != nil {
		cert.ParseError = err.Error()
	} else {
		cert.Parsed = parsed
	}
	hello.Certificate = cert
	specs := rest[certLength : certLength+specsLength]
	hello.CipherSpecsRaw = hex.EncodeToString(specs)
	for i := 0; i < len(specs); i += cipherSpecLength {
		hello.CipherSpecs = append(hello.CipherSpecs, cipherKindName(specs[i:i+cipherSpecLength]))
	}
	hello.ConnectionID = hex.EncodeToString(rest[certLength+specsLength:])
	return hello, nil
}
