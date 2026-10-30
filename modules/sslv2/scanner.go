// Package sslv2 provides a zgrab2 module that scans for SSL 2.0 servers.
// Default Port: 443 (TCP)
//
// The scanner opens a TCP connection and sends an SSL 2.0 CLIENT-HELLO; the
// exchange and its statuses are described in lib/sslv2. The output contains
// the SERVER-HELLO or the ERROR, the length of the record header, and the
// bytes read (up to 4096).
package sslv2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/sslv2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults = sslv2.Result

// Flags holds the command-line configuration for the SSL 2.0 scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("sslv2", "SSL 2.0",
		"Send an SSL 2.0 CLIENT-HELLO and read the server's SERVER-HELLO.", 443)
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
	}
	return nil
}

// Scan performs the SSL 2.0 scan.
//  1. Open a TCP connection to the target port (default 443).
//  2. Send a CLIENT-HELLO.
//  3. Read one record and check its SERVER-HELLO or ERROR.
//  4. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. SSL 2.0 requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	status, result, err := sslv2.Probe(conn)
	if err != nil {
		err = fmt.Errorf("%s: %w", target.String(), err)
	}
	return status, result, err
}
