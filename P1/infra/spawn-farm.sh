#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
N=${1:-20}

EXTRA_ENV="FARM_SIZE=$N" deploy sensorfarm r03 n09 0 \
  "/bin/bash /opt/ssle/farm.sh" services/temperature.py infra/farm.sh
