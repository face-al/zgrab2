package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/nntp"
)

func init() {
	zgrab2.RegisterModule(nntp.NewModule())
}
