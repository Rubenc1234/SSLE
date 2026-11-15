#!/usr/bin/env bash
source "$(dirname "$0")/infra/lib.sh"
mkdir -p evidencias/_logs
PROM=http://10.255.255.27:9090

infra_ok() {
  curl -s -m 5 http://10.255.255.1:9101/metrics | grep -q incus_container_memory_usage_bytes || return 1
  curl -s -m 5 -G "$PROM/api/v1/query" --data-urlencode 'query=incus_container_memory_usage_bytes' | grep -q '"value"' || return 2
  return 0
}

for job in "botnet wazuh_ar_ab_r2" "botnet wazuh_ar_ab_r3" "hijack wazuh_r2" "hijack wazuh_r3" "normal wazuh_r1"; do
  set -- $job
  LABEL="$1_$2"
  until [ "$(incus exec $REGISTRY -- iptables -L INPUT -n | grep -c DROP)" = 0 ] && [ "$(incus exec $INGESTION -- iptables -L INPUT -n | grep -c DROP)" = 0 ]; do
    sleep 10
  done
  
  infra_ok; irc=$?
  if [ "$irc" != 0 ]; then
    echo "=== $(date +%T) ABORTADO antes de $job: exporter/Prometheus sem dados de infra (codigo $irc)"
    exit 1
  fi
  
  echo "=== $(date +%T) INICIO $job | DROP registry=$(incus exec $REGISTRY -- iptables -L INPUT -n | grep -c DROP) ingestion=$(incus exec $INGESTION -- iptables -L INPUT -n | grep -c DROP) | infra OK"
  ./run_attack.sh "$1" "$2"
  rc=$?
  echo "=== $(date +%T) FIM $job (exit=$rc) $(grep -h data_ok evidencias/$LABEL/ssle_report_*.json 2>/dev/null | tr -d ' ' || echo 'data_ok=SEM_JSON')"
  sleep 120
done

echo "=== BATCH CONCLUIDO $(date +%T)"
