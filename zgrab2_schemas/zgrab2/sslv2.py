# zschema sub-schema for zgrab2's sslv2 module
# Registers zgrab2-sslv2 globally, and sslv2 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

sslv2_scan_response = SubRecord(
    {
        "result": SubRecord(zgrab2.sslv2_result)
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-sslv2", sslv2_scan_response)

zgrab2.register_scan_response_type("sslv2", sslv2_scan_response)
