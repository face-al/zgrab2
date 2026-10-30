# Base image for xmpp integration tests to avoid duplication of the same code in multiple Dockerfiles.
FROM zgrab2_service_base:latest

# Prosody serves the "localhost" VirtualHost and lists STARTTLS as required,
# but ships no certificate: give it the ssl-cert snakeoil pair, without which
# the TLS handshake fails.
RUN apt-get install -y \
  prosody

RUN cp /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/prosody/certs/localhost.crt && \
  cp /etc/ssl/private/ssl-cert-snakeoil.key /etc/prosody/certs/localhost.key && \
  chown root:prosody /etc/prosody/certs/localhost.crt /etc/prosody/certs/localhost.key && \
  chmod 640 /etc/prosody/certs/localhost.crt /etc/prosody/certs/localhost.key

# /run/prosody does not exist in the container.
RUN sed -i -e 's|^pidfile = .*|pidfile = "/tmp/prosody.pid";|' /etc/prosody/prosody.cfg.lua
