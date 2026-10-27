# zschema sub-schema for zgrab2's xmpp module
# Registers zgrab2-xmpp globally, and xmpp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

xmpp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(),
                "features": String(),
                "starttls_required": Boolean(),
                "stream_error": String(),
                "starttls": String(),
                "implicit_tls": Boolean(),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-xmpp", xmpp_scan_response)

zgrab2.register_scan_response_type("xmpp", xmpp_scan_response)
