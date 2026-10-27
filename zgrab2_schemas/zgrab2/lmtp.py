# zschema sub-schema for zgrab2's lmtp module
# Registers zgrab2-lmtp globally, and lmtp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

lmtp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(),
                "lhlo": String(),
                "starttls": String(),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-lmtp", lmtp_scan_response)

zgrab2.register_scan_response_type("lmtp", lmtp_scan_response)
