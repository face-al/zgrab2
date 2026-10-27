#!/usr/bin/env bash

set -e
MODULE_DIR=$(dirname $0)
ZGRAB_ROOT=$(git rev-parse --show-toplevel)
ZGRAB_OUTPUT=$ZGRAB_ROOT/zgrab-output

mkdir -p $ZGRAB_OUTPUT/nbd

CONTAINER_NAME=zgrab_nbd

OUTPUT_ROOT="$ZGRAB_OUTPUT/nbd"

function dumpDockerLogs() {
  # Dump the docker logs
  echo "nbd/test: BEGIN docker logs from $CONTAINER_NAME [{("
  docker logs --tail all $CONTAINER_NAME
  echo ")}] END docker logs from $CONTAINER_NAME"
}

function testQemuNBD() {
  CONTAINER_NAME=zgrab_nbd_qemu_nbd
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh nbd > $ZGRAB_OUTPUT/nbd/qemu-nbd.json
  dumpDockerLogs
}

function testQemuNBDAbort() {
  CONTAINER_NAME=zgrab_nbd_qemu_nbd
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh nbd --send-abort > $ZGRAB_OUTPUT/nbd/qemu-nbd-abort.json
  dumpDockerLogs
}

function testNBDKit() {
  CONTAINER_NAME=zgrab_nbd_nbdkit
  CONTAINER_NAME=$CONTAINER_NAME $ZGRAB_ROOT/docker-runner/docker-run.sh nbd > $ZGRAB_OUTPUT/nbd/nbdkit.json
  dumpDockerLogs
}
echo "nbd/test: Tests runner for nbd"

testQemuNBD
testQemuNBDAbort
testNBDKit

function checkFileForLackOfField() {
  FILE=$1
  FIELD=$2
  echo "check $FILE for lack of $FIELD"
  RESULT=$(jp data.nbd.result.$FIELD < $FILE)
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
  RESULT=$(jp -u data.nbd.$FIELD < $FILE)
  if [ "$RESULT" != "$VALUE" ]; then
    echo "Expected $FIELD = $VALUE, got $RESULT in $FILE [["
    cat $FILE
    echo "]]"
    exit 1
  fi
}

for file in $(find $OUTPUT_ROOT -iname "*.json"); do
  # Fixed newstyle, NBD_OPT_STARTTLS acknowledged, TLS negotiated
  checkFileForValue $file status success
  checkFileForValue $file result.negotiation fixed_newstyle
  checkFileForValue $file result.starttls.reply_name NBD_REP_ACK
  checkFileForValue $file result.tls.handshake_completed_successfully true
done

# NBD_OPT_ABORT only with --send-abort; qemu-nbd acknowledges it over TLS
checkFileForLackOfField $OUTPUT_ROOT/qemu-nbd.json abort
checkFileForLackOfField $OUTPUT_ROOT/nbdkit.json abort
checkFileForValue $OUTPUT_ROOT/qemu-nbd-abort.json result.abort.reply_name NBD_REP_ACK
