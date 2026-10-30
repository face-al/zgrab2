package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/sslv2"
)

func init() {
	zgrab2.RegisterModule(sslv2.NewModule())
}
