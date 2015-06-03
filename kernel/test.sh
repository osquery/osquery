#!/bin/bash

set -e;

if [[ $# -ne 3 ]]; then
  exit -1
fi

echo "Testing...."

make clean
make debug
make load
make -C user/ all

CONSUMER=$1
PRODUCER=$2
NUMBER=$3

sudo $CONSUMER &
CONSUMER_PID=$!
sleep 1;
PRODUCERS=()
RETPRODUCERS=0
RETCONSUMERS=0
for ((i=0;i<$NUMBER;i++)); do
  sudo $PRODUCER $((i%2)) &
  PRODUCERS[$i]=$!
done
wait ${PRODUCERS[@]} || RETPRODUCERS=$?
sudo pkill -2 -P $CONSUMER_PID || true
wait $CONSUMER_PID || RETCONSUMERS=$?

make unload

exit $(( RETPRODUCERS | RETCOSUMERS ))

