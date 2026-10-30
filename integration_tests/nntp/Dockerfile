# Base image for nntp integration tests to avoid duplication of the same code in multiple Dockerfiles.
FROM zgrab2_service_base:latest

RUN apt-get install -y \
  inn2 \
  openssl

# The container has no domain, so give INN one explicitly.
RUN sed -i -e 's|^#domain:.*|domain:                      example.com|' /etc/news/inn.conf

# The scanner connects from the compose network, so let any host read.
RUN printf '%s\n' \
  'auth "all" {' \
  '    hosts: "*"' \
  '    default: "<all>"' \
  '}' \
  'access "all" {' \
  '    users: "<all>"' \
  '    newsgroups: "*"' \
  '    access: R' \
  '}' \
  > /etc/news/readers.conf

# nnrpd answers "400 NNTP server unavailable" until the overview exists.
RUN su news -s /bin/sh -c "/usr/lib/news/bin/makehistory -O -x"

# Self-signed certificate for the TLS variants, at the default tlscertfile /
# tlskeyfile paths; nnrpd refuses a key that is world-readable.
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/news/key.pem \
    -out /etc/news/cert.pem \
    -subj "/C=US/ST=State/L=City/O=MyCompany/CN=nntp.example.com"; \
  chown news:news /etc/news/key.pem /etc/news/cert.pem; \
  chmod 640 /etc/news/key.pem
