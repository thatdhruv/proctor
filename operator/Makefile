GO ?= go
CONTROLLER_GEN_VERSION ?= v0.16.5

.PHONY: generate build test manifests
generate manifests:
	$(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION) object paths=./api/...
	$(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION) crd paths=./api/... output:crd:dir=config/crd
	$(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION) rbac:roleName=proctor-operator paths=./internal/... output:rbac:dir=config/rbac

build: generate
	CGO_ENABLED=0 $(GO) build -o bin/manager ./cmd

test: generate
	$(GO) vet ./...
	$(GO) test ./... -race -count=1
