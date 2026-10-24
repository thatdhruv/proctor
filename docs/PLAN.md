# Phase plan

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | Repo, architecture, plan, CI skeleton | Docs merged; `make test` wired |
| 1 | C++ sandbox: namespaces, rootfs, rlimits/cgroup, seccomp + user-notif logging | Sandbox runs `echo`; network & mount attempts denied and logged |
| 2 | `proctord` daemon: warm pool, snapshot/restore, JSON protocol; Python client | Cold vs warm latency benchmark runs |
| 3 | Environment API + 3 envs (coding, SQL/Postgres, FS-ops), host-side verifiers | `reset/step` pass tests with reference solutions |
| 4 | Postgres schema + recorder; OTel tracing + metrics | Episodes persisted; spans visible |
| 5 | Hardening loop: attacker, oracle, fixer, rounds | Cheating rate by exploit type, before/after |
| 6 | Containment red-team suite | Blocked attempts logged, 0 successes |
| 7 | Go operator + CRD + NetworkPolicy + quotas + autoscale | `go test` green; manifests validate |
| 8 | Observability stack (compose + Grafana dashboards) | Dashboards populated by real run |
| 9 | envharness adapter (credited, optional) | Adapter test passes |
| 10 | Evidence, diagrams, screenshots, README | Every number reproducible via `scripts/` |
