#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="attacker-pt-aveiro-dc1-r99-n99"
IMAGE="ssle-base"

echo "[+] A verificar se o contentor $CONTAINER_NAME já existe..."
if incus info "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "[+] Contentor já existe. A reiniciar..."
    incus restart "$CONTAINER_NAME"
else
    echo "[+] A criar o contentor do atacante a partir de $IMAGE..."
    incus launch "$IMAGE" "$CONTAINER_NAME"
    # Garantir que o sistema dentro do contentor está pronto
    incus exec "$CONTAINER_NAME" -- systemctl is-system-running --wait >/dev/null 2>&1 || true
fi

echo "[+] Contentor do atacante pronto a ser utilizado!"