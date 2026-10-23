# zschema sub-schema for zgrab2's ldap module
# Registers zgrab2-ldap globally, and ldap with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

ldap_extended_response = SubRecord(
    {
        "result_code": Signed32BitInteger(),
        "result_name": String(),
        "matched_dn": String(),
        "diagnostic_message": String(),
        "response_name": String(),
        "raw": String(),
    }
)

ldap_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "root_dse": SubRecord(
                    {
                        "result_code": Signed32BitInteger(),
                        "result_name": String(),
                        "diagnostic_message": String(),
                        "attributes": ListOf(
                            SubRecord(
                                {
                                    "name": String(),
                                    "values": ListOf(String()),
                                }
                            )
                        ),
                        "raw": String(),
                    }
                ),
                "starttls": ldap_extended_response,
                "notice_of_disconnection": ldap_extended_response,
                "implicit_tls": Boolean(),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-ldap", ldap_scan_response)

zgrab2.register_scan_response_type("ldap", ldap_scan_response)
