FROM zgrab2_ldap_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# No TLS configured, so StartTLS is not advertised

# Command to run slapd (-d keeps it in the foreground)
CMD ["slapd", "-h", "ldap:///", "-u", "openldap", "-g", "openldap", "-F", "/etc/ldap/slapd.d", "-d", "256"]
