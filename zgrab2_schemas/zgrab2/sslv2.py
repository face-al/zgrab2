# zschema sub-schema for zgrab2's sslv2 module
# Registers zgrab2-sslv2 globally, and sslv2 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

sslv2_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "server_hello": SubRecord(
                    {
                        "session_id_hit": Unsigned8BitInteger(),
                        "certificate_type": Unsigned8BitInteger(),
                        "version": Unsigned16BitInteger(),
                        "cipher_specs": ListOf(String()),
                        "cipher_specs_raw": String(),
                        "connection_id": String(),
                        "certificate": SubRecord(
                            {
                                "raw": Binary(),
                                "parsed": zcrypto.ParsedCertificate(),
                                "parse_error": String(),
                            }
                        ),
                    }
                ),
                "error": SubRecord(
                    {
                        "code": Unsigned16BitInteger(),
                        "name": String(),
                    }
                ),
                "header_len": Unsigned8BitInteger(),
                "raw": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-sslv2", sslv2_scan_response)

zgrab2.register_scan_response_type("sslv2", sslv2_scan_response)
