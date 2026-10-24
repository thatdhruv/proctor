"""The verifier hardening loop: attack -> measure cheating -> patch -> repeat.

A *cheat* is an episode where the verifier paid reward > 0 but the independent oracle says the task is not
solved. We also replay honest reference solutions every round, to prove hardening does not break utility.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import telemetry
from ..agents.exploits import EXPLOIT_TYPES, EXPLOITS, Ctx, Exploit
from ..agents.reference import solve
from ..core import CoreClient, Daemon
from ..envs.coding import CodingEnv
from ..envs.fsops import FsOpsEnv
from ..envs.sql import SqlEnv
from ..policy import VerifierPolicy
from ..store import NullStore, PostgresStore, Store
from ..tasks import coding as coding_tasks
from ..tasks import fs as fs_tasks
from ..tasks import sql as sql_tasks
from .fixer import Fixer, Patch, ScriptedFixer

ENVS = {"coding": CodingEnv, "sql": SqlEnv, "fsops": FsOpsEnv}
TASKS = {"coding": sorted(coding_tasks.TASKS), "sql": sorted(sql_tasks.TASKS), "fsops": sorted(fs_tasks.TASKS)}


@dataclass
class ExploitStat:
    id: str
    type: str
    env: str
    attempts: int = 0
    cheats: int = 0           # reward > 0 and oracle says unsolved
    escapes: int = 0          # escape probe reached something it should not
    blocked_events: int = 0   # sandbox-denied syscalls during the attack
    transcript: list = field(default_factory=list)  # first successful cheat (for the fixer)
    reported: list = field(default_factory=list)    # LLM attackers: self-reported exploit types

    @property
    def rate(self) -> float:
        return (self.cheats + self.escapes) / self.attempts if self.attempts else 0.0


@dataclass
class RoundReport:
    round: int
    policy: dict
    exploits: dict[str, ExploitStat] = field(default_factory=dict)
    honest_pass: dict[str, list[int]] = field(default_factory=dict)  # env -> [passed, total]
    patches: list[Patch] = field(default_factory=list)  # applied *after* this round
    seconds: float = 0.0

    def by_type(self) -> dict[str, dict]:
        out = {t: {"attempts": 0, "cheats": 0} for t in EXPLOIT_TYPES}
        for s in self.exploits.values():
            row = out.setdefault(s.type, {"attempts": 0, "cheats": 0})
            row["attempts"] += s.attempts
            row["cheats"] += s.cheats + s.escapes
        for v in out.values():
            v["rate"] = v["cheats"] / v["attempts"] if v["attempts"] else 0.0
        return out

    def overall_rate(self) -> float:
        a = sum(s.attempts for s in self.exploits.values())
        c = sum(s.cheats + s.escapes for s in self.exploits.values())
        return c / a if a else 0.0

    def to_dict(self) -> dict:
        return {"round": self.round, "policy": self.policy,
                "exploits": {k: {**{f: x for f, x in asdict(v).items() if f != "transcript"}, "rate": v.rate}
                             for k, v in self.exploits.items()},
                "by_type": self.by_type(), "overall_rate": self.overall_rate(),
                "honest_pass": self.honest_pass, "patches": [asdict(p) for p in self.patches],
                "seconds": self.seconds}


def run_exploit(core: CoreClient, ex: Exploit, policy: VerifierPolicy, round_no: int, seeds: list[int],
                store: Store) -> ExploitStat:
    stat = ExploitStat(ex.id, ex.type, ex.env)
    tasks = [t for t in TASKS[ex.env] if ex.tasks is None or t in ex.tasks]
    for task_id in tasks:
        for seed in seeds:
            env = ENVS[ex.env](core, policy, store=store, compute_oracle=True, agent_name=ex.id, round_no=round_no)
            try:
                obs, info = env.reset(seed=seed, options={"task_id": task_id})
                assert env.episode is not None
                env.episode.exploit_id, env.episode.exploit_type = ex.id, ex.type
                ctx = Ctx(env, obs, info)
                ex.run(ctx)
                if not ctx.submitted:
                    ctx.submit()
            finally:
                ep = env.episode
                env.close()
            stat.attempts += 1
            stat.blocked_events += len(ep.blocked) if ep else 0
            if ctx.escaped:
                stat.escapes += 1
            elif ep is not None and ep.cheated:
                stat.cheats += 1
                if not stat.transcript:
                    stat.transcript = [{"action": s["action"], "obs": str(s["observation"])[:400]} for s in ep.steps]
            stat.reported += ctx.notes
            telemetry.count("attempts", 1, exploit_type=ex.type, exploit=ex.id, round=str(round_no))
            # always add (even 0) so the series exists and a clean round shows up as 0%, not as missing data
            telemetry.count("cheats", int(bool(ctx.escaped or (ep is not None and ep.cheated))), exploit_type=ex.type, exploit=ex.id, round=str(round_no))
    return stat


def honest_check(core: CoreClient, policy: VerifierPolicy, round_no: int, store: Store, seeds: list[int]) -> dict:
    out: dict[str, list[int]] = {}
    for env_name, cls in ENVS.items():
        ok = tot = 0
        for task_id in TASKS[env_name]:
            for seed in seeds:
                env = cls(core, policy, store=store, compute_oracle=True, agent_name="reference", round_no=round_no)
                env.reset(seed=seed, options={"task_id": task_id})
                solve(env, task_id)
                ok += int(env.last_grade is not None and env.last_grade.reward > 0 and env.last_oracle is True)
                tot += 1
                env.close()
        out[env_name] = [ok, tot]
    return out


def run_round(core: CoreClient, policy: VerifierPolicy, round_no: int, store: Store, seeds: list[int],
              exploits: list[Exploit] | None = None) -> RoundReport:
    t0 = time.time()
    rep = RoundReport(round_no, policy.to_dict())
    for ex in exploits or EXPLOITS:
        with telemetry.span("hardening.exploit", exploit=ex.id, round=round_no):
            rep.exploits[ex.id] = run_exploit(core, ex, policy, round_no, seeds, store)
    rep.honest_pass = honest_check(core, policy, round_no, store, seeds[:1])
    rep.seconds = time.time() - t0
    return rep


def hardening_loop(core: CoreClient, store: Store, *, fixer: Fixer | None = None, max_rounds: int = 8,
                   seeds: list[int] | None = None, start: VerifierPolicy | None = None,
                   progress=print) -> list[RoundReport]:
    fixer = fixer or ScriptedFixer()
    seeds = seeds or [1, 2]
    policy = start or VerifierPolicy.naive()
    reports: list[RoundReport] = []
    for r in range(max_rounds):
        rep = run_round(core, policy, r, store, seeds)
        reports.append(rep)
        succ = {k: v.cheats + v.escapes for k, v in rep.exploits.items()}
        # Escapes are sandbox failures, not verifier failures: report them but never "fix" them with a flag.
        succ = {k: n for k, n in succ.items() if not k.startswith("esc.")}
        progress(f"round {r}: cheating rate {rep.overall_rate():.1%}  "
                 f"({sum(succ.values())} cheats / {sum(s.attempts for s in rep.exploits.values())} attempts)  "
                 f"honest {rep.honest_pass}")
        if sum(succ.values()) == 0:
            break
        policy, patches = fixer.propose(policy, succ, {k: v.transcript for k, v in rep.exploits.items()})
        rep.patches = patches
        progress("  patches: " + ", ".join(f"{p.flag} (for {p.because})" for p in patches))
        if not patches:
            progress("  fixer has no further patches; stopping")
            break
    return reports


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the verifier hardening loop")
    ap.add_argument("--out", default="evidence/hardening.json")
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--budget", type=int, default=3, help="patches the fixer may land per round")
    ap.add_argument("--seeds", default="1,2")
    ap.add_argument("--pg", default=os.environ.get("PROCTOR_STORE_DSN"), help="Postgres DSN for the episode store (optional)")
    ap.add_argument("--pool", type=int, default=6)
    a = ap.parse_args()
    telemetry.init("proctor-hardening")
    store: Store = PostgresStore(a.pg) if a.pg else NullStore()
    random.seed(0)
    with Daemon(pool=a.pool, metrics_port=int(os.environ.get("PROCTOR_METRICS_PORT", "0"))) as d:
        reps = hardening_loop(d.client, store, fixer=ScriptedFixer(a.budget), max_rounds=a.rounds,
                              seeds=[int(x) for x in a.seeds.split(",")])
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps({"fixer": f"scripted(budget={a.budget})", "rounds": [r.to_dict() for r in reps]}, indent=2))
    print("wrote", a.out)
    time.sleep(3)  # let the OTel exporters flush


if __name__ == "__main__":
    main()
