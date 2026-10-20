#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
sleep 10   # tempo para os serviços se registarem

incus file push "$ROOT/services/test_system.py" "$ANALYTICS/tmp/test_system.py"
incus exec "$ANALYTICS" -- env \
  REGISTRY="http://$REGISTRY.incus:5050" \
  INGESTION="http://$INGESTION.incus:5001" \
  STORAGE="http://$STORAGE.incus:5002" \
  ANALYTICS="http://$ANALYTICS.incus:5003" \
  python3 /tmp/test_system.py
