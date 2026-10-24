import inspect
import textwrap

import pytest

from proctor.core import CoreError, Daemon, find_build_dir
from proctor.envs.coding import CodingEnv
from proctor.policy import VerifierPolicy
from proctor.tasks import coding as ct

try:
    find_build_dir()
    HAVE_CORE = True
except CoreError:
    HAVE_CORE = False

pytestmark = pytest.mark.skipif(not HAVE_CORE, reason="C++ core not built")


@pytest.fixture(scope="module")
def daemon():
    with Daemon(pool=3) as d:
        yield d


POLICIES = {"naive": VerifierPolicy.naive(), "hardened": VerifierPolicy.hardened()}


def reference_source(task) -> str:
    helpers = {"merge_intervals": [], "is_balanced": [], "top_k_frequent": [],
               "roman_to_int": ["_R"], "rle_decode": [], "longest_common_prefix": []}
    out = ""
    for h in helpers[task.id]:
        out += f"{h} = {getattr(ct, h)!r}\n"
    out += inspect.getsource(task.ref)
    return out


@pytest.mark.parametrize("policy_name", POLICIES)
@pytest.mark.parametrize("task_id", sorted(ct.TASKS))
def test_honest_solution_always_rewarded(daemon, policy_name, task_id):
    """Hardening must never punish a real solution."""
    env = CodingEnv(daemon.client, POLICIES[policy_name], compute_oracle=True)
    env.reset(seed=3, options={"task_id": task_id})
    env.step({"type": "write_file", "path": "/workspace/solution.py", "content": reference_source(ct.TASKS[task_id])})
    _, reward, term, _, info = env.step({"type": "submit"})
    env.close()
    assert term and reward == 1.0, info
    assert env.last_oracle is True


@pytest.mark.parametrize("policy_name", POLICIES)
def test_untouched_stub_gets_no_reward(daemon, policy_name):
    env = CodingEnv(daemon.client, POLICIES[policy_name], compute_oracle=True)
    env.reset(seed=1, options={"task_id": "is_balanced"})
    _, reward, *_ = env.step({"type": "submit"})
    env.close()
    assert reward == 0.0 and env.last_oracle is False


def test_step_budget_truncates_and_grades(daemon):
    env = CodingEnv(daemon.client, VerifierPolicy.hardened(), max_steps=2)
    env.reset(seed=1)
    env.step({"type": "bash", "cmd": "true"})
    _, reward, term, trunc, _ = env.step({"type": "bash", "cmd": "true"})
    env.close()
    assert trunc and not term and reward == 0.0


def test_unknown_action_is_reported_not_raised(daemon):
    env = CodingEnv(daemon.client)
    env.reset(seed=1)
    obs, *_ = env.step({"type": "teleport"})
    env.close()
    assert "unknown action type" in obs["error"]
