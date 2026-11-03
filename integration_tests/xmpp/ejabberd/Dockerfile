FROM zgrab2_service_base:latest

# ejabberd serves "localhost" and requires STARTTLS out of the box, with a
# certificate generated at install time.
RUN apt-get install -y \
  ejabberd && \
  rm -rf /var/lib/apt/lists/*

# /run/ejabberd does not exist in the container.
RUN mkdir -p /run/ejabberd && chown ejabberd:ejabberd /run/ejabberd

# Run ejabberd in the foreground
CMD ["su", "-s", "/bin/sh", "ejabberd", "-c", "ejabberdctl foreground"]
