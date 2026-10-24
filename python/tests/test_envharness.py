import pytest

from proctor.agents.reference import coding_source
from proctor.core import CoreError, Daemon, find_build_dir

envharness = pytest.importorskip("envharness")

try:
    find_build_dir()
    HAVE_CORE = True
except CoreError:
    HAVE_CORE = False

pytestmark = pytest.mark.skipif(not HAVE_CORE, reason="C++ core not built")


@pytest.fixture(scope="module")
def daemon():
    with Daemon(pool=2) as d:
        yield d


def test_setup_layer_wraps_a_proctor_env(daemon):
    """EnvHarness's own `Setup` layer replays actions on reset on top of a Proctor environment."""
    from envharness.core.types import Action
    from envharness.harnesses.setup import Setup

    from proctor.integrations.envharness_adapter import ProctorActionableEnv

    base = ProctorActionableEnv("coding", core=daemon.client)
    env = Setup(base, actions=[Action(name="write_file", kwargs={"path": "/workspace/hint.txt", "content": "from-setup"})])
    first = env.reset(seed=3, options={"task_id": "is_balanced"})
    assert "is_balanced" in first.observation.text
    seen = env.step(Action(name="bash", kwargs={"cmd": "cat /workspace/hint.txt"}))
    assert seen.observation.text.strip() == "from-setup"
    assert env.evaluate().success is False

    env.step(Action(name="write_file", kwargs={"path": "/workspace/solution.py", "content": coding_source("is_balanced")}))
    done = env.step(Action(name="submit", kwargs={}))
    assert done.terminated and done.reward == 1.0
    assert env.evaluate().success is True
    env.close()


def test_save_state_roundtrip(daemon):
    from proctor.integrations.envharness_adapter import ProctorActionableEnv, set_default_core

    set_default_core(daemon.client)
    a = ProctorActionableEnv("fsops", core=daemon.client)
    a.reset(seed=5, options={"task_id": "clear_cache"})
    b = ProctorActionableEnv.from_state(a.save_state())
    assert b.default_reset_args() == (5, {"task_id": "clear_cache"})
    a.close()
    b.close()
