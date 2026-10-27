package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/xmpp"
)

func init() {
	zgrab2.RegisterModule(xmpp.NewModule())
}
