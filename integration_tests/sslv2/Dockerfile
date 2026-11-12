# OpenSSL 1.0.2u, the last release that can still be built with SSL 2.0
# (removed in 1.1.0), serving SSL 2.0 only.
FROM zgrab2_service_base:latest AS build

RUN apt-get install -y build-essential perl curl ca-certificates

RUN curl -fsSL -o /openssl.tar.gz https://github.com/openssl/openssl/releases/download/OpenSSL_1_0_2u/openssl-1.0.2u.tar.gz && \
  echo "ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16  /openssl.tar.gz" | sha256sum -c - && \
  tar -xzf /openssl.tar.gz -C / && \
  cd /openssl-1.0.2u && \
  ./config no-shared enable-ssl2 enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers && \
  make depend && make build_libs build_apps && \
  cp apps/openssl /openssl102

FROM zgrab2_service_base:latest

RUN apt-get install -y openssl

RUN openssl req -x509 -newkey rsa:2048 -nodes -keyout /key.pem -out /cert.pem -subj /CN=target -days 3650

COPY --from=build /openssl102 /usr/local/bin/openssl102

CMD ["openssl102", "s_server", "-accept", "443", "-ssl2", "-www", "-cert", "/cert.pem", "-key", "/key.pem"]
