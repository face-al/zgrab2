#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/irc

CONTAINER_NAME=zgrab_irc

OUTPUT_ROOT="$ZGRAB_OUTPUT/irc"

function dumpDockerLogs() {
  # Dump the docker logs
  echo "irc/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

function testSTARTTLS() {
  CONTAINER_NAME=zgrab_irc_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc > $ZGRAB_OUTPUT/irc/starttls.json
  dumpDockerLogs
  CONTAINER_NAME=zgrab_irc_no_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc > $ZGRAB_OUTPUT/irc/no_starttls.json
  dumpDockerLogs
}

function testIRCS() {
  CONTAINER_NAME=zgrab_irc_ircs
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh irc --ircs --port 6697 > $ZGRAB_OUTPUT/irc/ircs-tls.json
  dumpDockerLogs
}
echo "irc/test: Tests runner for irc"

testSTARTTLS
testIRCS

function checkFileForField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for $FIELD"
  RESULT=$(jp data.irc.result.$FIELD < $FILE)
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
  RESULT=$(jp data.irc.result.$FIELD < $FILE)
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
  RESULT=$(jp data.irc.result.tls.handshake_completed_successfully < $FILE)
  if [ "$RESULT" != "true" ]; then
    echo "TLS handshake did not complete in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

for file in $(find $OUTPUT_ROOT -iname "*.json"); do
  checkFileForField $file cap_ls
done

# STARTTLS advertised -> STARTTLS sent and TLS negotiated
checkFileForField $OUTPUT_ROOT/starttls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/starttls.json

# STARTTLS not advertised -> no STARTTLS, no TLS
checkFileForLackOfField $OUTPUT_ROOT/no_starttls.json starttls
checkFileForLackOfField $OUTPUT_ROOT/no_starttls.json tls

# Implicit TLS -> TLS negotiated before CAP LS, no STARTTLS
checkFileForField $OUTPUT_ROOT/ircs-tls.json implicit_tls
checkFileForLackOfField $OUTPUT_ROOT/ircs-tls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/ircs-tls.json
