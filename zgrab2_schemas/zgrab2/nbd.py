# zschema sub-schema for zgrab2's nbd module
# Registers zgrab2-nbd globally, and nbd with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

nbd_option_reply = SubRecord(
    {
        "option": Unsigned32BitInteger(),
        "reply_type": Unsigned32BitInteger(),
        "reply_name": String(),
        "message": String(),
        "raw": String(),
    }
)

nbd_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "greeting": String(),
                "negotiation": String(),
                "handshake_flags": Unsigned16BitInteger(),
                "starttls": nbd_option_reply,
                "abort": nbd_option_reply,
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-nbd", nbd_scan_response)

zgrab2.register_scan_response_type("nbd", nbd_scan_response)
