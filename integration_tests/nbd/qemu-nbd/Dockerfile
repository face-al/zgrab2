FROM zgrab2_nbd_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Serve with TLS required (FORCEDTLS); --persistent keeps serving after the first client.
CMD ["qemu-nbd", "--persistent", "--port=10809", "--format=raw", \
  "--object", "tls-creds-x509,id=tls0,dir=/pki,endpoint=server,verify-peer=off", \
  "--tls-creds", "tls0", "/disk.img"]
