import pytest

from proctor.agents.reference import FS_SOLUTIONS
from proctor.core import CoreError, Daemon, find_build_dir
from proctor.envs.fsops import FsOpsEnv
from proctor.policy import VerifierPolicy
from proctor.tasks.fs import TASKS

try:
    find_build_dir()
    HAVE_CORE = True
except CoreError:
    HAVE_CORE = False

pytestmark = pytest.mark.skipif(not HAVE_CORE, reason="C++ core not built")

SOLUTIONS = FS_SOLUTIONS


@pytest.fixture(scope="module")
def daemon():
    with Daemon(pool=2) as d:
        yield d


@pytest.mark.parametrize("pol", ["naive", "hardened"])
@pytest.mark.parametrize("task_id", sorted(TASKS))
def test_honest_solution_rewarded(daemon, pol, task_id):
    policy = VerifierPolicy.naive() if pol == "naive" else VerifierPolicy.hardened()
    env = FsOpsEnv(daemon.client, policy, compute_oracle=True)
    env.reset(seed=11, options={"task_id": task_id})
    obs, *_ = env.step({"type": "bash", "cmd": SOLUTIONS[task_id]})
    assert obs["exit_code"] == 0, obs
    _, reward, term, _, info = env.step({"type": "submit"})
    env.close()
    assert term and reward == 1.0, info
    assert env.last_oracle is True, env.episode.oracle_detail


@pytest.mark.parametrize("task_id", sorted(TASKS))
def test_doing_nothing_fails(daemon, task_id):
    env = FsOpsEnv(daemon.client, VerifierPolicy.hardened(), compute_oracle=True)
    env.reset(seed=11, options={"task_id": task_id})
    _, reward, *_ = env.step({"type": "submit"})
    env.close()
    assert reward == 0.0 and env.last_oracle is False
