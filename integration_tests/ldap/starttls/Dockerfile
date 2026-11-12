FROM zgrab2_ldap_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable StartTLS (advertised in the root DSE's supportedExtension)
RUN slapmodify -n0 -F /etc/ldap/slapd.d -l /etc/ldap/tls.ldif && \
  chown -R openldap:openldap /etc/ldap/slapd.d

# Command to run slapd (-d keeps it in the foreground)
CMD ["slapd", "-h", "ldap:///", "-u", "openldap", "-g", "openldap", "-F", "/etc/ldap/slapd.d", "-d", "256"]
