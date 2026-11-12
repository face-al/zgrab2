FROM zgrab2_nntp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable STARTTLS in reading mode
RUN sed -i -e 's|^#tlscertfile:|tlscertfile:|' -e 's|^#tlskeyfile:|tlskeyfile:|' /etc/news/inn.conf

# innd keeps its control socket and pid file here
RUN mkdir -p /run/news && chown news:news /run/news

USER news
# Command to run innd (in the foreground). innd is mode-switching: a feed
# peer (incoming.conf lists localhost, so the test scans 127.0.0.1) is greeted
# in transit mode and gets nnrpd, and with it STARTTLS, only after MODE READER.
# Port 119 is bound through the setuid innbind helper.
CMD ["/usr/lib/news/bin/innd", "-f", "-P", "119"]
