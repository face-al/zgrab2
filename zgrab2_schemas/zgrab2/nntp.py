# zschema sub-schema for zgrab2's nntp module
# Registers zgrab2-nntp globally, and nntp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

nntp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(),
                "capabilities": String(),
                "mode_reader": String(),
                "reader_capabilities": String(),
                "starttls": String(),
                "implicit_tls": Boolean(),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-nntp", nntp_scan_response)

zgrab2.register_scan_response_type("nntp", nntp_scan_response)
