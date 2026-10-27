#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/lmtp

CONTAINER_NAME=zgrab_lmtp

OUTPUT_ROOT="$ZGRAB_OUTPUT/lmtp"

function dumpDockerLogs() {
  # Dump the docker logs
  echo "lmtp/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

function testSTARTTLS() {
  CONTAINER_NAME=zgrab_lmtp_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh lmtp > $ZGRAB_OUTPUT/lmtp/starttls.json
  dumpDockerLogs
}

function testNoSTARTTLS() {
  CONTAINER_NAME=zgrab_lmtp_no_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh lmtp > $ZGRAB_OUTPUT/lmtp/no-starttls.json
  dumpDockerLogs
}
function testLMTPS() {
  CONTAINER_NAME=zgrab_lmtp_lmtps
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh lmtp --lmtps > $ZGRAB_OUTPUT/lmtp/lmtps-tls.json
  dumpDockerLogs
}
echo "lmtp/test: Tests runner for lmtp"

testSTARTTLS
testNoSTARTTLS
testLMTPS

function checkFileForField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for $FIELD"
  RESULT=$(jp data.lmtp.result.$FIELD < $FILE)
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
  RESULT=$(jp data.lmtp.result.$FIELD < $FILE)
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
  RESULT=$(jp data.lmtp.result.tls.handshake_completed_successfully < $FILE)
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
  RESULT=$(jp -u data.lmtp.status < $FILE)
  if [ "$RESULT" != "$STATUS" ]; then
    echo "Expected status $STATUS, got $RESULT in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

for file in $(find $OUTPUT_ROOT -iname "*.json"); do
  checkFileForField $file banner
  checkFileForField $file lhlo
done

# STARTTLS advertised -> STARTTLS sent and TLS negotiated
checkFileForStatus $OUTPUT_ROOT/starttls.json success
checkFileForField $OUTPUT_ROOT/starttls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/starttls.json

# ssl = no -> STARTTLS not advertised, not sent
checkFileForStatus $OUTPUT_ROOT/no-starttls.json success
checkFileForLackOfField $OUTPUT_ROOT/no-starttls.json starttls
checkFileForLackOfField $OUTPUT_ROOT/no-starttls.json tls

# Implicit TLS -> TLS negotiated before the greeting, no STARTTLS
checkFileForStatus $OUTPUT_ROOT/lmtps-tls.json success
checkFileForField $OUTPUT_ROOT/lmtps-tls.json implicit_tls
checkFileForLackOfField $OUTPUT_ROOT/lmtps-tls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/lmtps-tls.json
