FROM zgrab2_irc_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable implicit TLS on 6697
RUN printf '%s\n' \
  '<module name="ssl_gnutls">' \
  '<sslprofile name="Clients" provider="gnutls" certfile="/etc/inspircd/cert.pem" keyfile="/etc/inspircd/key.pem">' \
  '<bind address="" port="6697" type="clients" sslprofile="Clients">' \
  >> /etc/inspircd/inspircd.conf

USER irc
# Command to run inspircd (in the foreground)
CMD ["inspircd", "--nofork", "--config", "/etc/inspircd/inspircd.conf"]
