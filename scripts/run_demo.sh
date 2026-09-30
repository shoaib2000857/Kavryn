#!/usr/bin/env bash
# Uses only an existing checkout installation; no models or Docker are started.
set -euo pipefail

KAVRYN_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
KAVRYN_VENV="${KAVRYN_VENV:-${KAVRYN_ROOT}/.kavryn-venv}"
if [[ ! -x "${KAVRYN_VENV}/bin/kavryn" ]]; then
    echo "Install first with bash scripts/install.sh, or select KAVRYN_VENV." >&2
    exit 2
fi
"${KAVRYN_VENV}/bin/kavryn" demo "$@"
