# Phase plan

| Phase | Deliverable | Exit criteria | Status |
|---|---|---|---|
| 0 | Repo, architecture, plan, CI | docs merged; `make test` wired | done |
| 1 | C++ sandbox: namespaces, rootfs, rlimits/cgroup, seccomp + user-notif logging | `echo` runs; network and mount attempts denied and logged | done (15 integration checks) |
| 2 | `proctord`: warm pool, snapshot/restore, JSON protocol, Python client | cold vs warm benchmark runs | done: warm lease 0.18 ms vs cold 3.3 ms |
| 3 | Environment API + 3 envs (coding, SQL/Postgres, FS-ops) with host-side verifiers and oracles | honest solutions rewarded, stub gets 0 | done |
| 4 | Postgres episode store; OTel tracing + metrics | episodes persisted, spans visible | done |
| 5 | Hardening loop: attacker, oracle, fixer, rounds | cheating rate by exploit type before/after | done: 79% to 0% over 4 rounds (scripted adversary) |
| 6 | Containment red team | blocked attempts logged, 0 successes | done: 50/50 blocked, 29/29 logged |
| 7 | Go operator: CRD, sharding, autoscaling, quotas, NetworkPolicy | `go test` green; e2e on a real cluster | done (kind + Calico); fail-closed self-test added after finding that kindnet ignores policies |
| 8 | Observability stack | dashboards populated by a real run | done |
| 9 | envharness adapter (credited, optional) | adapter test passes against EnvHarness's own `Setup` layer | done |
| 10 | Evidence, diagrams, screenshots, README | every number reproducible | done |

## Next
* Run the LLM attacker and fixer against a live model and publish its cheating curve next to the scripted one.
* Let the fixer emit real code diffs, validated by regression (honest solutions) and exploit replay.
* Per-sandbox egress via a policy-enforcing proxy for tasks that legitimately need package installs.
* aarch64 build and test; gVisor/Kata `RuntimeClass` runs of the containment battery.
