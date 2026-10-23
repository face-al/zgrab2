FROM zgrab2_ldap_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable implicit TLS on 636
RUN slapmodify -n0 -F /etc/ldap/slapd.d -l /etc/ldap/tls.ldif && \
  chown -R openldap:openldap /etc/ldap/slapd.d

# Command to run slapd (-d keeps it in the foreground)
CMD ["slapd", "-h", "ldaps:///", "-u", "openldap", "-g", "openldap", "-F", "/etc/ldap/slapd.d", "-d", "256"]
