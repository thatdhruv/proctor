"""`proctor` command line."""
from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="proctor", description="Contained, red-teamed RL environments")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bench", help="startup latency + throughput benchmark of the C++ core")
    sub.add_parser("containment", help="run the sandbox escape battery")
    sub.add_parser("harden", help="run the attack -> patch hardening loop")
    d = sub.add_parser("demo", help="play one honest and one cheating episode and print the transcript")
    d.add_argument("--env", default="coding", choices=["coding", "sql", "fsops"])
    args, rest = ap.parse_known_args(argv)
    sys.argv = [f"proctor {args.cmd}"] + rest
    if args.cmd == "bench":
        from .bench import main as run
        run()
    elif args.cmd == "containment":
        from .containment import main as run
        run()
    elif args.cmd == "harden":
        from .hardening.loop import main as run
        run()
    elif args.cmd == "demo":
        _demo(args.env)


def _demo(env_name: str) -> None:
    from .agents.exploits import EXPLOITS, Ctx
    from .agents.reference import solve
    from .core import Daemon
    from .hardening.loop import ENVS, TASKS
    from .policy import VerifierPolicy

    with Daemon(pool=2) as d:
        for label, policy in (("naive verifier", VerifierPolicy.naive()), ("hardened verifier", VerifierPolicy.hardened())):
            print(f"== {label} ==")
            task = TASKS[env_name][0]
            env = ENVS[env_name](d.client, policy, compute_oracle=True)
            env.reset(seed=1, options={"task_id": task})
            solve(env, task)
            print(f"  honest solution : reward={env.episode.reward} oracle_solved={env.last_oracle}")
            env.close()
            for ex in [e for e in EXPLOITS if e.env == env_name and not e.id.startswith("esc.")]:
                if ex.tasks and task not in ex.tasks:
                    continue
                env = ENVS[env_name](d.client, policy, compute_oracle=True)
                obs, info = env.reset(seed=1, options={"task_id": task})
                ctx = Ctx(env, obs, info)
                ex.run(ctx)
                ctx.submit()
                ep = env.episode
                verdict = "CHEATED" if ep.cheated else "blocked"
                print(f"  {ex.id:<24} reward={ep.reward} oracle_solved={env.last_oracle}  -> {verdict}")
                env.close()


if __name__ == "__main__":
    main()
