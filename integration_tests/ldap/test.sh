#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/ldap

CONTAINER_NAME=zgrab_ldap

OUTPUT_ROOT="$ZGRAB_OUTPUT/ldap"

function dumpDockerLogs() {
  # Dump the docker logs
  echo "ldap/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

function testSTARTTLS() {
  CONTAINER_NAME=zgrab_ldap_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap > $ZGRAB_OUTPUT/ldap/starttls.json
  dumpDockerLogs
  CONTAINER_NAME=zgrab_ldap_no_starttls
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap > $ZGRAB_OUTPUT/ldap/no_starttls.json
  dumpDockerLogs
}

function testLDAPS() {
  CONTAINER_NAME=zgrab_ldap_ldaps
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh ldap --ldaps --port 636 > $ZGRAB_OUTPUT/ldap/ldaps-tls.json
  dumpDockerLogs
}
echo "ldap/test: Tests runner for ldap"

testSTARTTLS
testLDAPS

function checkFileForField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for $FIELD"
  RESULT=$(jp data.ldap.result.$FIELD < $FILE)
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
  RESULT=$(jp data.ldap.result.$FIELD < $FILE)
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
  RESULT=$(jp data.ldap.result.tls.handshake_completed_successfully < $FILE)
  if [ "$RESULT" != "true" ]; then
    echo "TLS handshake did not complete in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

function checkFileForValue() {
  FILE=$1
  FIELD=$2
  VALUE=$3
  echo "check $FILE for $FIELD = $VALUE"
  RESULT=$(jp -u data.ldap.$FIELD < $FILE)
  if [ "$RESULT" != "$VALUE" ]; then
    echo "Found $FIELD = $RESULT in $FILE, wanted $VALUE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

for file in $(find $OUTPUT_ROOT -iname "*.json"); do
  checkFileForValue $file status success
  checkFileForField $file root_dse.attributes
done

# StartTLS advertised -> StartTLS sent and TLS negotiated
checkFileForValue $OUTPUT_ROOT/starttls.json result.starttls.result_name success
checkFileForTLSHandshake $OUTPUT_ROOT/starttls.json

# StartTLS not advertised -> no StartTLS, no TLS
checkFileForLackOfField $OUTPUT_ROOT/no_starttls.json starttls
checkFileForLackOfField $OUTPUT_ROOT/no_starttls.json tls

# Implicit TLS -> TLS negotiated before the root DSE read, no StartTLS
checkFileForField $OUTPUT_ROOT/ldaps-tls.json implicit_tls
checkFileForLackOfField $OUTPUT_ROOT/ldaps-tls.json starttls
checkFileForTLSHandshake $OUTPUT_ROOT/ldaps-tls.json
