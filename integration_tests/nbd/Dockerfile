# Base image for nbd integration tests to avoid duplication of the same code in multiple Dockerfiles.
FROM zgrab2_service_base:latest

# qemu-nbd and nbdkit do STARTTLS without asking for a client certificate;
# nbd-server always asks for one, so it is not used here.
RUN apt-get install -y \
  qemu-utils \
  nbdkit \
  openssl

# qemu-nbd wants a CA certificate with CA:TRUE next to the server's.
RUN mkdir /pki && cd /pki && \
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-key.pem -out ca-cert.pem -subj /CN=ca -days 3650 \
    -addext basicConstraints=critical,CA:TRUE && \
  openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj /CN=target -addext subjectAltName=DNS:target && \
  openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem -days 3650 -copy_extensions copy && \
  chmod 644 /pki/*.pem

RUN truncate -s 1M /disk.img
