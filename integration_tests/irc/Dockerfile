# Base image for irc integration tests to avoid duplication of the same code in multiple Dockerfiles.
FROM zgrab2_service_base:latest

RUN apt-get install -y \
  inspircd \
  openssl

# Self-signed certificate for the TLS variants
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/inspircd/key.pem \
    -out /etc/inspircd/cert.pem \
    -subj "/C=US/ST=State/L=City/O=MyCompany/CN=irc.example.com"; \
  chown irc /etc/inspircd/key.pem /etc/inspircd/cert.pem

# Minimal plaintext server on 6667; the cap module answers CAP LS.
RUN printf '%s\n' \
  '<server name="irc.local" description="zgrab2 test server" network="Localnet">' \
  '<admin name="zgrab2" description="zgrab2" email="zgrab2@localhost">' \
  '<pid file="/tmp/inspircd.pid">' \
  '<connect allow="*" timeout="60">' \
  '<bind address="" port="6667" type="clients">' \
  '<module name="cap">' \
  > /etc/inspircd/inspircd.conf
