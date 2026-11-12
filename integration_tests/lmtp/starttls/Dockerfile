FROM zgrab2_lmtp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Run dovecot in the foreground
CMD ["dovecot", "-F"]
