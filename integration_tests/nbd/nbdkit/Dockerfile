FROM zgrab2_nbd_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Serve in the foreground with TLS required.
CMD ["nbdkit", "--foreground", "--port=10809", "--tls=require", "--tls-certificates=/pki", "memory", "1M"]
