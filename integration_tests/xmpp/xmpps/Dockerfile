FROM zgrab2_xmpp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable direct TLS (XEP-0368) on the default port instead of plaintext, as
# no port is assigned to it. Global options must come before the first
# VirtualHost.
RUN sed -i -e '/^VirtualHost "localhost"/i c2s_ports = { }\nc2s_direct_tls_ports = { 5222 }' /etc/prosody/prosody.cfg.lua

# Run prosody in the foreground
CMD ["su", "-s", "/bin/sh", "prosody", "-c", "prosody -F"]
