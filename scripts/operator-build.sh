#!/usr/bin/env bash
# Initialise (first run), generate deepcopy/CRD/RBAC, vet and test the Go operator.
set -euo pipefail
export PATH="$HOME/sdk/go/bin:/usr/local/bin:/usr/bin:/bin"
export GOFLAGS=-mod=mod GOTOOLCHAIN=local
cd "$(dirname "${BASH_SOURCE[0]}")/../operator"
if [ ! -f go.mod ]; then
  go mod init proctor.dev/operator
  go get sigs.k8s.io/controller-runtime@v0.19.3 k8s.io/api@v0.31.3 k8s.io/apimachinery@v0.31.3 k8s.io/client-go@v0.31.3
fi
go mod tidy 2>&1 | tail -3 || true
make generate
go mod tidy
go vet ./...
go test ./... -race -count=1 "$@"
