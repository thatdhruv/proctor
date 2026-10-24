#!/usr/bin/env bash
# Install kind into ~/sdk/bin (via the Go toolchain) and create a 3-node cluster for the operator e2e test.
set -euo pipefail
export PATH="$HOME/sdk/go/bin:$HOME/sdk/bin:/usr/local/bin:/usr/bin:/bin"
export GOBIN="$HOME/sdk/bin" GOTOOLCHAIN=local
command -v kind >/dev/null || go install sigs.k8s.io/kind@v0.24.0
command -v kubectl >/dev/null || curl -sSL -o "$GOBIN/kubectl" "https://dl.k8s.io/release/v1.31.2/bin/linux/amd64/kubectl" && chmod +x "$GOBIN/kubectl"
kind version; kubectl version --client 2>&1 | head -1
