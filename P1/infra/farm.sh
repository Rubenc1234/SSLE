#!/usr/bin/env bash
N=${FARM_SIZE:-20}
for i in $(seq 1 "$N"); do
  rack="r0$((i % 3 + 1))"; node=$(printf 'n%02d' "$i")
  DEVICE_ID="farm-pt-aveiro-dc1-${rack}-${node}" RACK="$rack" NODE="$node" \
    python3 /opt/ssle/temperature.py &
done
wait
