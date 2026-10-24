#!/usr/bin/env bash
# Installs user-local toolchains (no sudo): uv + Python venv, and the Go SDK.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.local/bin:$HOME/sdk/go/bin:$PATH"

if ! command -v uv >/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

GO_VERSION=1.23.4
if [ ! -x "$HOME/sdk/go/bin/go" ]; then
  mkdir -p "$HOME/sdk"
  curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C "$HOME/sdk" -xz
fi

# The venv lives outside the (Windows-mounted) repo for speed.
VENV="${PROCTOR_VENV:-$HOME/.venvs/proctor}"
if [ ! -d "$VENV" ]; then
  uv venv --python 3.12 "$VENV"
fi
uv pip install --python "$VENV/bin/python" -e "$ROOT/python[dev]"
echo "uv: $(uv --version)"; echo "go: $(go version)"; echo "python: $("$VENV/bin/python" --version)"
