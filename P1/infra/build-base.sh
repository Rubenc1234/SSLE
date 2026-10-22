#!/usr/bin/env bash
set -euo pipefail

# lança contentor "base" e verifica se consegue aceder a deb.debian.org (DNS)
incus launch images:debian/trixie base >/dev/null
until incus exec base -- getent hosts deb.debian.org >/dev/null 2>&1; do sleep 1; done

# instala dependências, logrotate e cria utilizador ssle
incus exec base -- bash -c '
    apt-get update &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-flask python3-requests curl sqlite3 logrotate &&
    useradd --system --no-create-home --home-dir /var/lib/ssle \
        --shell /usr/sbin/nologin ssle &&
    mkdir -p /opt/ssle /etc/ssle /etc/systemd/journald.conf.d /var/log/ssle &&
    chown -R ssle:ssle /var/log/ssle &&
    printf "[Journal]\nSystemMaxUse=50M\n" > /etc/systemd/journald.conf.d/size.conf &&
    printf "/var/log/ssle/access.log {\n    size 10M\n    rotate 3\n    copytruncate\n    compress\n    missingok\n    notifempty\n}\n" > /etc/logrotate.d/ssle &&
    apt-get clean
'

# cria imagem 'base' do contentor 'base', para dps ser reutilizada na criação de outros contentores
incus stop base
incus publish base --alias ssle-base
incus delete base
echo "Imagem ssle-base criada."
