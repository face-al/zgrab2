FROM zgrab2_lmtp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable implicit TLS: no port is registered for LMTP over TLS, so wrap the
# listener on 24 itself, as for any other port the server picks.
RUN printf '%s\n' \
  'service lmtp {' \
  '  inet_listener lmtp {' \
  '    port = 24' \
  '    ssl = yes' \
  '  }' \
  '}' \
  > /etc/dovecot/local.conf

# Run dovecot in the foreground
CMD ["dovecot", "-F"]
