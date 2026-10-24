"""Optional layer: expose a Proctor environment as a Google `envharness` ActionableEnv.

Credit: this module plugs into **EnvHarness** by Google Research
(https://github.com/google-research/envharness, Apache-2.0). EnvHarness defines the `ActionableEnv`
interface and composable "harness" layers (`Setup`, `Rules`, `Link`, ...) that wrap a frozen benchmark
without editing it. Proctor only *adapts* its environments to that interface so that EnvHarness layers can
be stacked on top; it does not reimplement EnvHarness, its layers, or its LLM-driven harness search
(the "EnvRigger" idea). Install EnvHarness separately; it is not vendored here.

    from envharness.harnesses.setup import Setup
    env = Setup(ProctorActionableEnv("coding", core=client), actions=[Action(name="bash", kwargs={...})])
"""
from __future__ import annotations

from typing import Any

try:
    from envharness.core.actionable_env import ActionableEnv
    from envharness.core.registry import register_env
    from envharness.core.types import Action, EnvResetResponse, EnvResponse, EvaluationResult, Observation
except ImportError as e:  # pragma: no cover - exercised only when envharness is absent
    raise ImportError(
        "proctor.integrations.envharness_adapter needs Google's envharness: "
        "pip install git+https://github.com/google-research/envharness") from e

from ..core import CoreClient
from ..envs.base import ProctorEnv
from ..envs.coding import CodingEnv
from ..envs.fsops import FsOpsEnv
from ..envs.sql import SqlEnv
from ..policy import VerifierPolicy

ENV_CLASSES: dict[str, type[ProctorEnv]] = {"coding": CodingEnv, "sql": SqlEnv, "fsops": FsOpsEnv}
_default_core: CoreClient | None = None


def set_default_core(client: CoreClient) -> None:
    """Used by `from_state`, which has no other way to obtain a live connection to proctord."""
    global _default_core
    _default_core = client


@register_env("proctor")
class ProctorActionableEnv(ActionableEnv):
    """Adapter: Proctor's reset()/step() tuple API -> EnvHarness's pydantic request/response types."""

    def __init__(self, env_name: str = "coding", policy: VerifierPolicy | None = None,
                 core: CoreClient | None = None, max_steps: int = 20, compute_oracle: bool = False) -> None:
        core = core or _default_core
        if core is None:
            raise RuntimeError("pass core=CoreClient(...) or call set_default_core()")
        self.env_name = env_name
        self.policy = policy or VerifierPolicy.hardened()
        self._max_steps = max_steps
        self._env: ProctorEnv = ENV_CLASSES[env_name](core, self.policy, max_steps=max_steps,
                                                       compute_oracle=compute_oracle)
        self._reset_args: tuple[int | None, dict] = (None, {})
        self._last_obs: dict = {}
        self._prompt = ""
        self._reward = 0.0
        self._finished = False

    # -------------------------------------------------------------- step loop
    def reset(self, seed: int | None = None, options: dict[str, Any] | None = None) -> EnvResetResponse:
        self._reset_args = (seed, dict(options or {}))
        obs, info = self._env.reset(seed=seed, options=options)
        self._last_obs, self._reward, self._finished = obs, 0.0, False
        self._prompt = obs["prompt"]
        return EnvResetResponse(observation=Observation(text=obs["prompt"], data=dict(obs)), info=dict(info))

    def step(self, action: Action) -> EnvResponse:
        obs, reward, terminated, truncated, info = self._env.step({"type": action.name, **action.kwargs})
        self._last_obs = obs
        self._reward += reward
        self._finished = terminated or truncated
        text = "\n".join(x for x in (str(obs.get("stdout", "")), str(obs.get("stderr", "")),
                                     str(obs.get("error", ""))) if x)
        return EnvResponse(observation=Observation(text=text, data=dict(obs)), reward=reward,
                           terminated=terminated, truncated=truncated, info=dict(info))

    def observe(self) -> Observation:
        # Fresh view of the world: the task statement plus the latest tool output.
        return Observation(text=self._prompt, data={**self._last_obs, "prompt": self._prompt})

    def notify_replay_complete(self) -> None:
        """EnvHarness's Setup layer replays actions inside reset(); do not charge them to the step budget."""
        self._env._steps = 0
        if self._env.episode is not None:
            self._env.episode.steps.clear()

    def evaluate(self) -> EvaluationResult:
        g = self._env.last_grade
        if g is None:
            return EvaluationResult(success=False, score=0.0, metrics={"finished": False})
        return EvaluationResult(success=g.passed, score=g.reward,
                                metrics={"finished": True, "verifier": g.detail, "oracle_solved": self._env.last_oracle})

    def get_env_state(self) -> Any:
        # Data only (no sandbox handle / sockets), as the EnvHarness contract requires.
        return {"env": self.env_name, "task_id": self._env.task_id, "steps": self._env._steps,
                "policy": self.policy.to_dict(), "reward_so_far": self._reward}

    # ------------------------------------------------------------- save / load
    def save_state(self) -> dict:
        seed, options = self._reset_args
        return {"env_name": self.env_name, "policy": self.policy.to_dict(), "max_steps": self._max_steps,
                "reset_seed": seed, "reset_options": options}

    @classmethod
    def from_state(cls, state: dict) -> "ProctorActionableEnv":
        env = cls(state["env_name"], VerifierPolicy(**state["policy"]), max_steps=state.get("max_steps", 20))
        env._reset_args = (state.get("reset_seed"), dict(state.get("reset_options") or {}))
        return env

    def default_reset_args(self) -> tuple[int | None, dict]:
        return self._reset_args

    def close(self) -> None:
        self._env.close()
