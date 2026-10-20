#!/usr/bin/env bash

# carregar funções aux defenidas em infra/lib.sh
source "$(dirname "$0")/lib.sh"

PY="/usr/bin/python3 /opt/ssle"

# criar os serviços
# deploy <tipo> <rack> <nó> <porta> <comando> <ficheiro>...
deploy registry  r01 n01 5050 "$PY/serviceRegistry.py"   services/serviceRegistry.py
sleep 2
deploy storage   r02 n01 5002 "$PY/storageService.py"    services/storageService.py
deploy ingestion r01 n02 5001 "$PY/ingestionService.py"  services/ingestionService.py
deploy analytics r02 n02 5003 "$PY/analyticsService.py"  services/analyticsService.py

deploy sensor r02 n03 0 "$PY/temperature.py" services/temperature.py
deploy sensor r03 n01 0 "$PY/temperature.py" services/temperature.py

# listar os contentores criados
echo; incus list -c n4s
