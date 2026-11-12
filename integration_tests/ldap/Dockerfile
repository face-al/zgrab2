# Base image for ldap integration tests to avoid duplication of the same code in multiple Dockerfiles.
FROM zgrab2_service_base:latest

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
  slapd \
  openssl

# Self-signed certificate for the TLS variants
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/ldap/key.pem \
    -out /etc/ldap/cert.pem \
    -subj "/C=US/ST=State/L=City/O=MyCompany/CN=ldap.example.com"; \
  chown openldap /etc/ldap/key.pem /etc/ldap/cert.pem

# TLS configuration for the TLS variants; the certificate and key must be set
# in one modification, as slapd checks that they match.
RUN printf '%s\n' \
  'dn: cn=config' \
  'changetype: modify' \
  'replace: olcTLSCertificateFile' \
  'olcTLSCertificateFile: /etc/ldap/cert.pem' \
  '-' \
  'replace: olcTLSCertificateKeyFile' \
  'olcTLSCertificateKeyFile: /etc/ldap/key.pem' \
  > /etc/ldap/tls.ldif

# slapd writes its pid file here
RUN mkdir -p /var/run/slapd && chown openldap:openldap /var/run/slapd
