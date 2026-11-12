FROM zgrab2_xmpp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Run prosody in the foreground
CMD ["su", "-s", "/bin/sh", "prosody", "-c", "prosody -F"]
