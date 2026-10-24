#!/usr/bin/env bash
# Run a command inside the dev venv with the C++ core on the path (used from Windows via `wsl -- bash scripts/wsl-exec.sh ...`).
export PATH="$HOME/.local/bin:$HOME/sdk/go/bin:/usr/local/bin:/usr/bin:/bin"
export PROCTOR_CORE_BUILD="${PROCTOR_CORE_BUILD:-$HOME/pb}"
export PROCTOR_VENV="${PROCTOR_VENV:-$HOME/.venvs/proctor}"
export PATH="$PROCTOR_VENV/bin:$PATH"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec "$@"
