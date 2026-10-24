"""Gymnasium-style environment base class: reset() / step()."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .. import telemetry
from ..core import CoreClient, CoreError, ExecResult, Sandbox
from ..policy import VerifierPolicy
from ..store import EpisodeRecord, NullStore, Store, jsonable

MAX_OBS_CHARS = 8000


@dataclass
class Grade:
    reward: float
    passed: bool
    detail: dict = field(default_factory=dict)


def clip(s: str, n: int = MAX_OBS_CHARS) -> str:
    return s if len(s) <= n else s[: n // 2] + f"\n...[{len(s) - n} chars truncated]...\n" + s[-n // 2:]


class ProctorEnv:
    """reset() -> (obs, info); step(action) -> (obs, reward, terminated, truncated, info).

    Actions are dicts: {"type": "bash"|"python"|"write_file"|"read_file"|"sql"|"submit", ...}.
    Reward is sparse: it is issued once, when the episode ends (submit or step budget).
    `oracle()` is an independent ground-truth check that is never shown to the agent.
    """

    name = "base"
    action_types: tuple[str, ...] = ("bash", "python", "write_file", "read_file", "submit")

    def __init__(self, core: CoreClient, policy: VerifierPolicy | None = None, store: Store | None = None,
                 max_steps: int = 20, compute_oracle: bool = False, agent_name: str = "", round_no: int | None = None):
        self.core = core
        self.policy = policy or VerifierPolicy.naive()
        self.store = store or NullStore()
        self.max_steps = max_steps
        self.compute_oracle = compute_oracle
        self.agent_name = agent_name
        self.round_no = round_no
        self.sb: Sandbox | None = None
        self.episode: EpisodeRecord | None = None
        self.task_id = ""
        self.seed = 0
        self._steps = 0
        self._done = True
        self.last_grade: Grade | None = None
        self.last_oracle: bool | None = None

    # ------------------------------------------------------------ to implement
    def task_ids(self) -> list[str]:
        raise NotImplementedError

    def _start(self, task_id: str, seed: int) -> str:
        """Provision the task; return the prompt shown to the agent."""
        raise NotImplementedError

    def _act(self, action: dict) -> dict:
        raise NotImplementedError

    def _submit(self, action: dict) -> dict:
        """Hook: capture whatever the agent submits (default: nothing, state is read at grading)."""
        return {}

    def _grade(self) -> Grade:
        raise NotImplementedError

    def _oracle(self) -> tuple[bool, dict]:
        raise NotImplementedError

    def _cleanup(self) -> None:
        pass

    # --------------------------------------------------------------- gym API
    def reset(self, *, seed: int | None = None, options: dict | None = None) -> tuple[dict, dict]:
        self.close()
        options = options or {}
        self.seed = int(seed if seed is not None else time.time_ns() % 1_000_000)
        ids = self.task_ids()
        self.task_id = options.get("task_id") or ids[self.seed % len(ids)]
        with telemetry.span("env.reset", env=self.name, task=self.task_id), telemetry.Timer() as tm:
            self.sb = self.core.acquire()
            prompt = self._start(self.task_id, self.seed)
            telemetry.set_attrs(sandbox_source=self.sb.source, acquire_ms=self.sb.acquire_ms)
        telemetry.observe("startup", tm.dt, env=self.name, source=self.sb.source)
        self._steps = 0
        self._done = False
        self.last_grade = None
        self.last_oracle = None
        self.episode = EpisodeRecord(env=self.name, task_id=self.task_id, seed=self.seed, agent=self.agent_name,
                                     round=self.round_no, policy=self.policy.to_dict())
        info = {"task_id": self.task_id, "sandbox_source": self.sb.source, "acquire_ms": self.sb.acquire_ms,
                "action_types": list(self.action_types)}
        return {"prompt": prompt, "step": 0}, info

    def step(self, action: dict) -> tuple[dict, float, bool, bool, dict]:
        if self._done or self.sb is None:
            raise RuntimeError("call reset() before step()")
        self._steps += 1
        atype = str(action.get("type", ""))
        t0 = time.perf_counter()
        denied_before = len(self.sb.denied())
        with telemetry.span("env.step", env=self.name, task=self.task_id, action=atype, step=self._steps):
            if atype == "submit":
                obs = {**self._submit(action), "message": "submitted"}
            elif atype in self.action_types:
                try:
                    obs = self._act(action)
                except CoreError as e:
                    obs = {"error": str(e)}
            else:
                obs = {"error": f"unknown action type {atype!r}; allowed: {list(self.action_types)}"}
            blocked_now = len(self.sb.denied()) - denied_before
            telemetry.set_attrs(denied_syscalls=blocked_now, exit_code=obs.get("exit_code"))
            if blocked_now:
                telemetry.add_event("sandbox.blocked", count=blocked_now)
                telemetry.count("blocked", blocked_now, env=self.name)
        latency = (time.perf_counter() - t0) * 1000
        telemetry.count("steps", 1, env=self.name, action=atype)
        telemetry.observe("step_dur", latency / 1000, env=self.name, action=atype)

        terminated = atype == "submit"
        truncated = not terminated and self._steps >= self.max_steps
        reward = 0.0
        info: dict[str, Any] = {"denied_syscalls": blocked_now}
        if terminated or truncated:
            reward = self._finish(info)
        obs = {**obs, "step": self._steps}
        assert self.episode is not None
        self.episode.steps.append({"step": self._steps, "action": jsonable(action), "observation": jsonable(obs),
                                   "reward": reward, "latency_ms": latency, "denied": blocked_now})
        if terminated or truncated:
            self._store_episode()
        return obs, reward, terminated, truncated, info

    def _finish(self, info: dict) -> float:
        with telemetry.span("env.grade", env=self.name, task=self.task_id):
            self.last_grade = self._grade()
        reward = self.last_grade.reward
        info["verifier"] = self.last_grade.detail
        assert self.episode is not None
        self.episode.reward = reward
        self.episode.reward_detail = self.last_grade.detail
        if self.compute_oracle:
            with telemetry.span("env.oracle", env=self.name, task=self.task_id):
                self.last_oracle, odetail = self._oracle()
            self.episode.oracle_solved = self.last_oracle
            self.episode.oracle_detail = odetail
        self._done = True
        telemetry.count("episodes", 1, env=self.name, solved=str(self.last_grade.passed).lower())
        return reward

    def _store_episode(self) -> None:
        ep = self.episode
        if ep is None:
            return
        if self.sb is not None:
            for e in self.sb.denied():
                ep.blocked.append({**e, "sandbox": self.sb.id})
        self.store.write_episode(ep)

    def close(self) -> None:
        if self.sb is not None:
            try:
                self._cleanup()
            finally:
                try:
                    self.sb.release()
                except CoreError:
                    pass
                self.sb = None
        self._done = True

    # --------------------------------------------------- shared sandbox actions
    def _sandbox_action(self, action: dict) -> dict:
        assert self.sb is not None
        t = action["type"]
        if t == "bash":
            return self._obs(self.sb.bash(action.get("cmd", ""), timeout_ms=int(action.get("timeout_ms", 10_000))))
        if t == "python":
            return self._obs(self.sb.exec(["/usr/bin/python3", "-c", action.get("code", "")],
                                          timeout_ms=int(action.get("timeout_ms", 10_000))))
        if t == "write_file":
            self.sb.write_file(action["path"], action.get("content", ""))
            return {"exit_code": 0, "stdout": "", "stderr": ""}
        if t == "read_file":
            return {"exit_code": 0, "stdout": clip(self.sb.read_file(action["path"]).decode("utf-8", "replace")),
                    "stderr": ""}
        raise CoreError(f"unsupported action {t}")

    @staticmethod
    def _obs(r: ExecResult) -> dict:
        return {"exit_code": r.exit_code, "stdout": clip(r.stdout), "stderr": clip(r.stderr),
                "timed_out": r.timed_out, "denied": len(r.denied)}
