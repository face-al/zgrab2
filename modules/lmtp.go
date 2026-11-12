package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/lmtp"
)

func init() {
	zgrab2.RegisterModule(lmtp.NewModule())
}
