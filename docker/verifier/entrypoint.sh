#!/bin/sh
# Fixed, reviewed entrypoint for the clean-room verifier image. Takes no
# untrusted string arguments (docs/TOOLS_AND_SANDBOXES.md: "avoid shell
# expansion unless the adapter itself has a reviewed fixed script") --
# every path here is a container-internal mount point, never derived
# from request/candidate content.
#
# Reconstructs the candidate from the TRUSTED base source (read-only,
# /base) and the candidate's diff (read-only, /candidate/patch.diff)
# itself, independently of whatever the patch worker already built --
# this container never receives or trusts an already-patched tree.
set -e

cp -r /base "$HOME/scratch"
cd "$HOME/scratch"

if ! patch --quiet --strip=1 --forward --input /candidate/patch.diff; then
    echo "AEGIS_VERIFIER: patch did not apply cleanly" >&2
    exit 2
fi

if ! python -c "import app" > /dev/null 2>&1; then
    echo "AEGIS_VERIFIER: patched source failed to import" >&2
    exit 2
fi

export PYTHONPATH="$HOME/scratch"
cd /
python -m pytest /tests/public /tests/hidden --junitxml="$HOME/report.xml" -q \
    > "$HOME/pytest.log" 2>&1 || true
cat "$HOME/report.xml"
