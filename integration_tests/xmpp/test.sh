#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/xmpp

CONTAINER_NAME=zgrab_xmpp

OUTPUT_ROOT="$ZGRAB_OUTPUT/xmpp"

# The servers serve only "localhost"; any other 'to', such as the target
# name, gets a host-unknown stream error.
DOMAIN_FLAG=--xmpp-domain=localhost

function dumpDockerLogs() {
  # Dump the docker logs
  echo "xmpp/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

function testSTARTTLS() {
  CONTAINER_NAME=zgrab_xmpp_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh xmpp $DOMAIN_FLAG > $ZGRAB_OUTPUT/xmpp/starttls.json
  dumpDockerLogs
}

function testNoSTARTTLS() {
  CONTAINER_NAME=zgrab_xmpp_no_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh xmpp $DOMAIN_FLAG > $ZGRAB_OUTPUT/xmpp/no-starttls.json
  dumpDockerLogs
}

function testXMPPS() {
  CONTAINER_NAME=zgrab_xmpp_xmpps
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh xmpp --xmpps $DOMAIN_FLAG > $ZGRAB_OUTPUT/xmpp/xmpps-tls.json
  dumpDockerLogs
}

function testEjabberd() {
  CONTAINER_NAME=zgrab_xmpp_ejabberd
  # ejabberd takes several seconds to start listening.
  for i in $(seq 1 60); do
    if docker exec -u ejabberd $CONTAINER_NAME ejabberdctl status > /dev/null 2>&1; then
      break
    fi
    if [ $i -eq 60 ]; then
      echo "xmpp/test: ejabberd did not start"
      dumpDockerLogs
      exit 1
    fi
    sleep 1
  done
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh xmpp $DOMAIN_FLAG > $ZGRAB_OUTPUT/xmpp/ejabberd.json
  dumpDockerLogs
}

echo "xmpp/test: Tests runner for xmpp"

testSTARTTLS
testNoSTARTTLS
testXMPPS
testEjabberd

function checkFileForField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for $FIELD"
  RESULT=$(jp data.xmpp.result.$FIELD < $FILE)
  if [ "$RESULT" = "null" ]; then
    echo "Did not find $FIELD in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

function checkFileForLackOfField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for lack of $FIELD"
  RESULT=$(jp data.xmpp.result.$FIELD < $FILE)
  if [ "$RESULT" != "null" ]; then
    echo "Did find $FIELD in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

function checkFileForTLSHandshake() {
  FILE=$1
  echo "check $FILE for a completed TLS handshake"
  RESULT=$(jp data.xmpp.result.tls.handshake_completed_successfully < $FILE)
  if [ "$RESULT" != "true" ]; then
    echo "TLS handshake did not complete in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

function checkFileForStatus() {
  FILE=$1
  STATUS=$2
  echo "check $FILE for status $STATUS"
  RESULT=$(jp -u data.xmpp.status < $FILE)
  if [ "$RESULT" != "$STATUS" ]; then
    echo "Expected status $STATUS, got $RESULT in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

for file in $(find $OUTPUT_ROOT -iname "*.json"); do
  checkFileForField $file banner
  checkFileForField $file features
  checkFileForLackOfField $file stream_error
done

# STARTTLS advertised as required -> STARTTLS sent and TLS negotiated
for file in $OUTPUT_ROOT/starttls.json $OUTPUT_ROOT/ejabberd.json; do
  checkFileForStatus $file success
  checkFileForField $file starttls
  checkFileForField $file starttls_required
  checkFileForTLSHandshake $file
done

# mod_tls disabled -> STARTTLS not advertised, not sent
checkFileForStatus $OUTPUT_ROOT/no-starttls.json success
checkFileForLackOfField $OUTPUT_ROOT/no-starttls.json starttls
checkFileForLackOfField $OUTPUT_ROOT/no-starttls.json tls

# Direct TLS -> TLS negotiated before the stream header, no STARTTLS
checkFileForStatus $OUTPUT_ROOT/xmpps-tls.json success
checkFileForField $OUTPUT_ROOT/xmpps-tls.json implicit_tls
checkFileForLackOfField $OUTPUT_ROOT/xmpps-tls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/xmpps-tls.json
