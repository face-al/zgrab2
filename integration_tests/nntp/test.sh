#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/nntp

CONTAINER_NAME=zgrab_nntp

OUTPUT_ROOT="$ZGRAB_OUTPUT/nntp"

function dumpDockerLogs() {
  # Dump the docker logs
  echo "nntp/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

function testSTARTTLS() {
  CONTAINER_NAME=zgrab_nntp_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh nntp > $ZGRAB_OUTPUT/nntp/starttls.json
  dumpDockerLogs
}

function testNNTPS() {
  CONTAINER_NAME=zgrab_nntp_nntps
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh nntp --nntps --port 563 > $ZGRAB_OUTPUT/nntp/nntps-tls.json
  dumpDockerLogs
}
echo "nntp/test: Tests runner for nntp"

testSTARTTLS
testNNTPS

function checkFileForField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for $FIELD"
  RESULT=$(jp data.nntp.result.$FIELD < $FILE)
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
  RESULT=$(jp data.nntp.result.$FIELD < $FILE)
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
  RESULT=$(jp data.nntp.result.tls.handshake_completed_successfully < $FILE)
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
  RESULT=$(jp -u data.nntp.status < $FILE)
  if [ "$RESULT" != "$STATUS" ]; then
    echo "Expected status $STATUS, got $RESULT in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

for file in $(find $OUTPUT_ROOT -iname "*.json"); do
  checkFileForField $file banner
  checkFileForField $file capabilities
done

# STARTTLS advertised -> STARTTLS sent and TLS negotiated
checkFileForStatus $OUTPUT_ROOT/starttls.json success
checkFileForField $OUTPUT_ROOT/starttls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/starttls.json

# Implicit TLS -> TLS negotiated before the greeting, no STARTTLS
checkFileForStatus $OUTPUT_ROOT/nntps-tls.json success
checkFileForField $OUTPUT_ROOT/nntps-tls.json implicit_tls
checkFileForLackOfField $OUTPUT_ROOT/nntps-tls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/nntps-tls.json
