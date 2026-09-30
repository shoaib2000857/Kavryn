#!/usr/bin/env bash
# Operator-run local installation; never fetch-and-execute this script blindly.
set -euo pipefail

KAVRYN_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
KAVRYN_VENV="${KAVRYN_VENV:-${KAVRYN_ROOT}/.kavryn-venv}"
KAVRYN_PYTHON="${KAVRYN_PYTHON:-python3}"

"${KAVRYN_PYTHON}" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
if [[ -e "${KAVRYN_VENV}" ]]; then
    echo "Refusing to overwrite an existing installation path; choose a new KAVRYN_VENV." >&2
    exit 2
fi
"${KAVRYN_PYTHON}" -m venv "${KAVRYN_VENV}"
"${KAVRYN_VENV}/bin/python" -m pip install "${KAVRYN_ROOT}"
"${KAVRYN_VENV}/bin/kavryn" doctor
echo "Installed locally. Run: ${KAVRYN_VENV}/bin/kavryn demo"
