#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
TEST_ROOT=$MODULE_DIR/..
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

CONTAINER_NAME="zgrab_ftp"

# Run the FTP-specific integration tests:
# 1. Run zgrab2 on the container

mkdir -p $ZGRAB_OUTPUT/ftp

OUTPUT_DIR="$ZGRAB_OUTPUT/ftp"

echo "ftp/test: Testing FTP with --authtls on $CONTAINER_NAME..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ftp --authtls > $OUTPUT_DIR/authtls.json

echo "ftp/test: Testing FTP on $CONTAINER_NAME..."
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ftp > $OUTPUT_DIR/default.json

echo "ftp/test: BEGIN vsftpd logs from $CONTAINER_NAME [{("
docker exec $CONTAINER_NAME cat //var/log/vsftpd.log
echo ")}] END vsftpd logs from $CONTAINER_NAME"

echo "ftp/test: BEGIN docker logs from $CONTAINER_NAME [{("
docker logs --tail all $CONTAINER_NAME
echo ")}] END docker logs from $CONTAINER_NAME"

# The smtp module's --ftp-fallback against the same FTP server: EHLO is
# refused, AUTH TLS granted with 234, so the server is marked FTP and the TLS
# handshake follows. Kept outside $OUTPUT_DIR, whose files are ftp scans.
echo "ftp/test: Testing smtp --ftp-fallback on $CONTAINER_NAME..."
mkdir -p $ZGRAB_OUTPUT/ftp-smtp
FILE=$ZGRAB_OUTPUT/ftp-smtp/ftp-fallback.json
CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh smtp --port 21 --send-ehlo-override --ftp-fallback > $FILE
for CHECK in "data.smtp.status=\"success\"" "data.smtp.result.ftp=true" "data.smtp.result.tls.handshake_completed_successfully=true"; do
  if [ "$(jp ${CHECK%%=*} < $FILE)" != "${CHECK#*=}" ]; then
    echo "Expected ${CHECK} in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
done
(cd $ZGRAB_ROOT && python3 -m zschema validate zgrab2 $FILE --path . --module zgrab2_schemas.zgrab2)
