FROM zgrab2_nntp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Enable STARTTLS
RUN sed -i -e 's|^#tlscertfile:|tlscertfile:|' -e 's|^#tlskeyfile:|tlskeyfile:|' /etc/news/inn.conf

USER news
# Command to run nnrpd as a standalone daemon (in the foreground)
CMD ["/usr/lib/news/bin/nnrpd", "-D", "-f", "-p", "119"]
