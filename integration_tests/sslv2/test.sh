#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/sslv2

CONTAINER_NAME=zgrab_sslv2

OUTPUT_ROOT="$ZGRAB_OUTPUT/sslv2"

function dumpDockerLogs() {
  # Dump the docker logs
  echo "sslv2/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

echo "sslv2/test: Tests runner for sslv2"

CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh sslv2 > $OUTPUT_ROOT/sslv2.json
dumpDockerLogs

function checkFileForLackOfField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for lack of $FIELD"
  RESULT=$(jp data.sslv2.result.$FIELD < $FILE)
  if [ "$RESULT" != "null" ]; then
    echo "Did find $FIELD in $FILE [["
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
  RESULT=$(jp -u data.sslv2.$FIELD < $FILE)
  if [ "$RESULT" != "$VALUE" ]; then
    echo "Expected $FIELD = $VALUE, got $RESULT in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

# OpenSSL 1.0.2u s_server -ssl2 answers the CLIENT-HELLO with a SERVER-HELLO
FILE=$OUTPUT_ROOT/sslv2.json
checkFileForValue $FILE status success
checkFileForValue $FILE result.header_len 2
checkFileForValue $FILE result.server_hello.session_id_hit 0
checkFileForValue $FILE result.server_hello.certificate_type 1
checkFileForValue $FILE result.server_hello.version 2
checkFileForValue $FILE "result.server_hello.cipher_specs[0]" SSL_CK_RC4_128_WITH_MD5
checkFileForValue $FILE "length(result.server_hello.connection_id)" 32
checkFileForValue $FILE result.server_hello.certificate.parsed.subject.common_name[0] target
checkFileForLackOfField $FILE server_hello.certificate.parse_error
checkFileForLackOfField $FILE error
