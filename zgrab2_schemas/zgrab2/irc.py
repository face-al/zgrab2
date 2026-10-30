# zschema sub-schema for zgrab2's irc module
# Registers zgrab2-irc globally, and irc with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

irc_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "cap_ls": String(),
                "starttls": String(),
                "implicit_tls": Boolean(),
                "tls": zgrab2.tls_log,
                "sslv2": zgrab2.sslv2_upgrade,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-irc", irc_scan_response)

zgrab2.register_scan_response_type("irc", irc_scan_response)
