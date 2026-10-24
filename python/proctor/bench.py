"""Benchmarks for the execution core: startup latency (cold vs warm) and rollout throughput.

    python -m proctor.bench --out evidence/core_bench.json
"""
from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from pathlib import Path

from .core import CoreClient, Daemon


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summarize(xs: list[float]) -> dict:
    return {"n": len(xs), "mean": statistics.fmean(xs), "p50": pct(xs, 50), "p90": pct(xs, 90),
            "p99": pct(xs, 99), "min": min(xs), "max": max(xs)}


def startup(d: Daemon, n: int) -> dict:
    c = d.client
    cold, cold_first, warm, warm_first, restore = [], [], [], [], []
    for _ in range(n):
        t = time.perf_counter()
        sb = c.acquire(cold=True)
        cold.append((time.perf_counter() - t) * 1000)
        sb.exec(["/bin/true"])
        cold_first.append((time.perf_counter() - t) * 1000)
        sb.release(reuse=False)
    for _ in range(n):
        d.wait_pool(d.client.stats()["pool_target"])
        t = time.perf_counter()
        sb = c.acquire()
        warm.append((time.perf_counter() - t) * 1000)
        assert sb.source == "warm", "pool was empty during the warm benchmark"
        sb.exec(["/bin/true"])
        warm_first.append((time.perf_counter() - t) * 1000)
        sb.release(reuse=False)
    # snapshot-restore: reuse one sandbox with a populated workspace
    sb = c.acquire(cold=True)
    for i in range(20):
        sb.write_file(f"/workspace/src/mod{i}.py", "x = 1\n" * 200)
    sb.snapshot()
    for _ in range(n):
        sb.bash("echo junk > /workspace/junk; rm -f /workspace/src/mod0.py")
        restore.append(sb.restore())
    sb.release(reuse=False)
    return {"cold_acquire_ms": summarize(cold), "cold_to_first_result_ms": summarize(cold_first),
            "warm_acquire_ms": summarize(warm), "warm_to_first_result_ms": summarize(warm_first),
            "snapshot_restore_ms": summarize(restore)}


def throughput(sock: str, workers: int, seconds: float, mode: str) -> dict:
    """Each worker loops: lease a sandbox, run a tiny command, release. mode: warm|cold."""
    counts = [0] * workers
    stop = time.time() + seconds

    def work(i: int) -> None:
        c = CoreClient(sock)
        while time.time() < stop:
            sb = c.acquire(cold=(mode == "cold"))
            sb.exec(["/bin/true"])
            sb.release(reuse=(mode != "cold"))
            counts[i] += 1
        c.close()

    ts = [threading.Thread(target=work, args=(i,)) for i in range(workers)]
    t0 = time.time()
    [t.start() for t in ts]
    [t.join() for t in ts]
    el = time.time() - t0
    return {"workers": workers, "mode": mode, "episodes": sum(counts), "seconds": el,
            "steps_per_sec": sum(counts) / el}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--pool", type=int, default=8)
    ap.add_argument("--seconds", type=float, default=5.0)
    ap.add_argument("--workers", default="1,2,4,8,16")
    ap.add_argument("--out", default="evidence/core_bench.json")
    a = ap.parse_args()
    with Daemon(pool=a.pool) as d:
        res: dict = {"pool": a.pool, "cgroup": d.client.acquire(cold=True).info["sandbox"]["cgroup"]}
        res["startup"] = startup(d, a.n)
        res["throughput"] = []
        for w in [int(x) for x in a.workers.split(",")]:
            for mode in ("warm", "cold"):
                r = throughput(d.socket_path, w, a.seconds, mode)
                print(r)
                res["throughput"].append(r)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    print(json.dumps(res["startup"], indent=2))


if __name__ == "__main__":
    main()
