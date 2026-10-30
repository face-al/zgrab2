FROM zgrab2_irc_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# No TLS modules loaded, so the "tls" capability is not advertised

USER irc
# Command to run inspircd (in the foreground)
CMD ["inspircd", "--nofork", "--config", "/etc/inspircd/inspircd.conf"]
