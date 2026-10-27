FROM zgrab2_lmtp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Disable TLS, which drops STARTTLS from the LHLO reply
RUN sed -i -e 's|^ssl = yes|ssl = no|' /etc/dovecot/conf.d/10-ssl.conf

# Run dovecot in the foreground
CMD ["dovecot", "-F"]
