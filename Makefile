# Top-level convenience targets. Linux (or WSL2) is required for the core.
.PHONY: core test test-core test-python test-operator up down evidence report
core:
	$(MAKE) -C core
test: test-core test-python test-operator
test-core: core
	python3 core/tests/run_tests.py core/build
test-python: core
	cd python && PROCTOR_CORE_BUILD=$(CURDIR)/core/build python -m pytest -q tests
test-operator:
	$(MAKE) -C operator test
up:
	docker compose -f deploy/docker-compose.yml up -d
down:
	docker compose -f deploy/docker-compose.yml down -v
# Reproduce the numbers in the README (needs `make up`).
evidence: core
	cd python && python -m proctor.bench --out ../evidence/core_bench.json
	cd python && python -m proctor.containment --out ../evidence/containment
	cd python && python -m proctor.hardening.loop --out ../evidence/hardening.json
report:
	cd python && python -m proctor.report --evidence ../evidence --out ../docs/images
