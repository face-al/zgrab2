FROM zgrab2_nntp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable implicit TLS on 563
RUN sed -i -e 's|^#tlscertfile:|tlscertfile:|' -e 's|^#tlskeyfile:|tlskeyfile:|' /etc/news/inn.conf

USER news
# Command to run nnrpd as a standalone daemon (in the foreground), with TLS
# as soon as a client connects
CMD ["/usr/lib/news/bin/nnrpd", "-D", "-f", "-p", "563", "-S"]
