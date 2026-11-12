# Base image for lmtp integration tests to avoid duplication of the same code in multiple Dockerfiles.
FROM zgrab2_service_base:latest

# dovecot-lmtpd ships with ssl = yes and the ssl-cert snakeoil certificate,
# so STARTTLS is offered on LHLO unless a variant turns it off.
RUN apt-get install -y \
  dovecot-lmtpd

# Dovecot listens for LMTP on a UNIX socket only; add a TCP listener on 24.
RUN printf '%s\n' \
  'service lmtp {' \
  '  inet_listener lmtp {' \
  '    port = 24' \
  '  }' \
  '}' \
  > /etc/dovecot/local.conf
