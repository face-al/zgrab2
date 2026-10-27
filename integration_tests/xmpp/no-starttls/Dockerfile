FROM zgrab2_xmpp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Disable mod_tls, which drops STARTTLS from the stream features. Global
# options must come before the first VirtualHost.
RUN sed -i -e '/^VirtualHost "localhost"/i modules_disabled = { "tls" }\nc2s_require_encryption = false' /etc/prosody/prosody.cfg.lua

# Run prosody in the foreground
CMD ["su", "-s", "/bin/sh", "prosody", "-c", "prosody -F"]
