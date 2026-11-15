
#!/usr/bin/env bash
# reprocess.sh - recalcula as metricas de corridas ja feitas com a janela certa,
# sem repetir o ataque (o Prometheus ainda tem os dados, se dentro da retencao).
#
# Uso:
#   ./reprocess.sh --dry-run
#   ./reprocess.sh
#   ./reprocess.sh evidencias/botnet_wazuh_ar_a_r1

set -u
cd "$(dirname "$0")"

DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
if [ "$#" -gt 0 ]; then DIRS=("$@"); else DIRS=(evidencias/*/); fi

for d in "${DIRS[@]}"; do
  d=${d%/}
  name=$(basename "$d")
  case "$name" in _*) continue ;; esac

  meta="$d/meta.txt"
  [ -f "$meta" ] || { echo "[SKIP] $name: sem meta.txt"; continue; }

  type=${name%%_*}
  case "$type" in
    dos|normal)    W=150; OFF=130 ;;
    botnet|hijack) W=90;  OFF=70  ;;
    *) echo "[SKIP] $name: tipo '$type' desconhecido"; continue ;;
  esac

  # Instante de referencia: at_epoch ou start
  AT=$(grep -m1 '^at_epoch=' "$meta" | cut -d= -f2- | tr -d ' \r')
  if [ -z "$AT" ]; then
    start=$(grep -m1 '^start=' "$meta" | cut -d= -f2- | tr -d '\r')
    start=${start# }
    if [[ "$start" =~ ^[0-9]{9,}$ ]]; then
      START=$start
    elif [[ "$start" =~ ^[0-9]{4}- ]]; then
      START=$(date -d "$start" +%s 2>/dev/null)
    elif [[ "$start" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
      day=$(date -r "$meta" +%F)
      START=$(date -d "$day $start" +%s 2>/dev/null)
    else
      echo "[SKIP] $name: formato de start nao reconhecido: '$start'"; continue
    fi
    [ -n "${START:-}" ] || { echo "[SKIP] $name: nao consegui calcular start"; continue; }
    AT=$(( START + OFF ))
  fi

  echo "[..] $name: tipo=$type janela=${W}s at=$AT ($(date -d @"$AT" '+%F %T'))"
  [ "$DRY" -eq 1 ] && continue

  out="$d/ssle_report_w${W}.json"
  python3 monitoring/collect_baseline.py --label reproc_tmp --window "${W}s" --at "$AT" \
      > "$d/reprocess_w${W}.log" 2>&1

  if [ -f ssle_report_reproc_tmp.json ]; then
    mv ssle_report_reproc_tmp.json "$out"
  else
    echo "[ERRO] $name: o collect nao gerou JSON (ver $d/reprocess_w${W}.log)"; continue
  fi

  python3 - "$out" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
x, b = d.get("ingestion_extra", {}), d.get("business", {})
f = lambda v: "N/A" if v is None else f"{v:.0f}"
print(f"     data_ok={d.get('data_ok')} ingest={f(x.get('ingest_requests_window'))} "
      f"2xx={f(x.get('ingest_2xx_window'))} pico_rps45={x.get('ingest_peak_rps_45s')} "
      f"sensores={f(b.get('sensor_registrations_window'))} "
      f"unicos={f(b.get('storage_unique_devices'))} overwrites={f(b.get('registry_overwrites'))}")
EOF
done

