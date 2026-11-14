#!/usr/bin/env bash
# uso: ./infra/install_wazuh_agent.sh <contentor> <wazuh_ip> <versao>
set -euo pipefail
NAME=$1; WAZUH_IP=$2; VER=$3

incus exec "$NAME" -- bash -c "
    set -e
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gpg curl iptables
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
        --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER='$WAZUH_IP' WAZUH_AGENT_NAME='$NAME' \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wazuh-agent=$VER
"

incus exec "$NAME" -- bash -c '
    if ! grep -q "/var/log/ssle/access.log" /var/ossec/etc/ossec.conf; then
        cat >> /var/ossec/etc/ossec.conf <<EOF

<ossec_config>
    <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/ssle/access.log</location>
    </localfile>
</ossec_config>
EOF
    fi
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl restart wazuh-agent
'

sleep 10
echo "--- estado do agente em $NAME ---"
incus exec "$NAME" -- grep -a "status=" /var/ossec/var/run/wazuh-agentd.state || \
    echo "(ficheiro de estado não encontrado, vê o dashboard)"