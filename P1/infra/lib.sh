#!/usr/bin/env bash
set -euo pipefail

# Root directory of the project
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=ssle-base
COUNTRY=pt; REGION=aveiro; DC=dc1

# cname <tipo> ... <rack> <nó>  ->  storage-pt-aveiro-dc1-r02-n01
cname() { echo "$1-$COUNTRY-$REGION-$DC-$2-$3"; }

REGISTRY=$(cname registry r01 n01)
INGESTION=$(cname ingestion r01 n02)
STORAGE=$(cname storage r02 n01)
ANALYTICS=$(cname analytics r02 n02)
REGISTRY_URL="http://$REGISTRY.incus:5050"

# deploy <tipo> <rack> <nó> <porta> <comando> <ficheiro>...
# Variável opcional EXTRA_ENV (linhas KEY=VALUE) acrescenta ao /etc/ssle/env
deploy() {
    local type=$1 rack=$2 node=$3 port=$4 exec_cmd=$5; shift 5
    local name; name=$(cname "$type" "$rack" "$node")

    # verifica se já existe um contentor com o mesmo nome e apaga-o, e lança um novo contentor com a imagem base
    if incus info "$name" >/dev/null 2>&1; then incus delete -f "$name"; fi
    incus launch "$IMAGE" "$name" >/dev/null
    # espera que o contentor esteja pronto (systemd)
    incus exec "$name" -- systemctl is-system-running --wait >/dev/null 2>&1 || true

    # Criar o ficheiro de env do serviço -> /etc/ssle/env
    {
        echo "SERVICE_NAME=${type}-service"
        echo "SERVICE_ID=$name"
        echo "DEVICE_ID=$name"
        echo "SERVICE_TYPE=$type"
        echo "SERVICE_URL=http://$name.incus:$port"
        echo "REGISTRY_URL=$REGISTRY_URL"
        echo "COUNTRY=$COUNTRY"
        echo "REGION=$REGION"
        echo "DC=$DC"
        echo "RACK=$rack"
        echo "NODE=$node"
        echo "DB_PATH=/var/lib/ssle/temp_data.db"
        echo "PYTHONUNBUFFERED=1"
        [ -n "${EXTRA_ENV:-}" ] && echo "$EXTRA_ENV"
    } | incus exec "$name" -- tee /etc/ssle/env >/dev/null

    # Copiar para o contentor todos os ficheiros indicados nos argumentos
    # incus file push "$ROOT/services/serviceRegistry.py" \ registry-pt-aveiro-dc1-r01-n01/opt/ssle/
    for f in "$@"; do
        incus file push "$ROOT/$f" "$name/opt/ssle/"
    done

    # Preparar a configuração do serviço systemd
    sed "s|@EXEC@|$exec_cmd|" "$ROOT/infra/ssle.service" \
        | incus exec "$name" -- tee /etc/systemd/system/ssle.service >/dev/null
    incus exec "$name" -- systemctl daemon-reload
    incus exec "$name" -- systemctl enable --now ssle >/dev/null

    echo "OK  $name"
}
