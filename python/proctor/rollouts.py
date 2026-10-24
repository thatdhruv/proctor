"""Parallel rollout generator: honest reference agents running full episodes against the hardened verifiers.

    proctor rollouts --workers 8 --seconds 60 --out evidence/rollouts.json

Measures end-to-end throughput (env.step() calls and episodes per second, including sandbox leases, grading
and the oracle) and feeds the Grafana dashboard / Postgres store when those are configured.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import threading
import time
from collections import Counter
from pathlib import Path

from . import telemetry
from .agents.reference import solve
from .core import CoreClient, Daemon
from .hardening.loop import ENVS, TASKS
from .policy import VerifierPolicy
from .store import NullStore, PostgresStore

RECON = {"coding": [{"type": "bash", "cmd": "ls -la /workspace"}, {"type": "read_file", "path": "/workspace/TASK.md"},
                    {"type": "bash", "cmd": "python3 -m unittest discover -s tests 2>&1 | tail -3"}],
         "fsops": [{"type": "bash", "cmd": "ls -R /workspace | head -40"}, {"type": "bash", "cmd": "du -sh /workspace"}],
         "sql": [{"type": "sql", "query": "SELECT count(*) FROM customers"}, {"type": "sql", "query": "SELECT count(*) FROM orders"}]}
MIX = [("coding", 0.6), ("fsops", 0.25), ("sql", 0.15)]


def worker(sock: str, deadline: float, seed0: int, store, oracle: bool, stats: Counter, lock: threading.Lock,
           mix) -> None:
    rng = random.Random(seed0)
    client = CoreClient(sock)
    policy = VerifierPolicy.hardened()
    names, weights = zip(*mix)
    while time.time() < deadline:
        env_name = rng.choices(names, weights)[0]
        task = rng.choice(TASKS[env_name])
        env = ENVS[env_name](client, policy, store=store, compute_oracle=oracle, agent_name="reference")
        try:
            env.reset(seed=rng.randint(1, 10**6), options={"task_id": task})
            steps = 0
            for a in RECON[env_name]:
                env.step(a)
                steps += 1
            solve(env, task)
            steps += 2
            ok = env.last_grade is not None and env.last_grade.reward > 0
        finally:
            env.close()
        with lock:
            stats["episodes"] += 1
            stats["steps"] += steps
            stats["solved"] += int(ok)
            stats[f"episodes_{env_name}"] += 1
    client.close()


def run(workers: int, seconds: float, pool: int, oracle: bool, store, mix=MIX) -> dict:
    stats: Counter = Counter()
    lock = threading.Lock()
    metrics_port = int(os.environ.get("PROCTOR_METRICS_PORT", "0"))
    with Daemon(pool=pool, metrics_port=metrics_port) as d:
        t0 = time.time()
        deadline = t0 + seconds
        ts = [threading.Thread(target=worker, args=(d.socket_path, deadline, 100 + i, store, oracle, stats, lock, mix))
              for i in range(workers)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        el = time.time() - t0
        cg = d.client.acquire(cold=True)
        cgroup = cg.info["sandbox"]["cgroup"]
        cg.release(reuse=False)
    return {"workers": workers, "seconds": el, "oracle": oracle, "cgroup": cgroup, **stats,
            "steps_per_sec": stats["steps"] / el, "episodes_per_sec": stats["episodes"] / el}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--pool", type=int, default=16)
    ap.add_argument("--oracle", action="store_true", help="also run the oracle each episode (slower)")
    ap.add_argument("--no-sql", action="store_true", help="skip the SQL env (no Postgres needed)")
    ap.add_argument("--out", default="evidence/rollouts.json")
    a = ap.parse_args()
    telemetry.init("proctor-rollouts")
    dsn = os.environ.get("PROCTOR_STORE_DSN")
    store = PostgresStore(dsn) if dsn else NullStore()
    mix = [m for m in MIX if not (a.no_sql and m[0] == "sql")]
    res = run(a.workers, a.seconds, a.pool, a.oracle, store, mix)
    print(json.dumps(res, indent=2))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    import time as _t
    _t.sleep(3)  # let the OTel exporters flush


if __name__ == "__main__":
    main()
