import os

import pytest

from proctor.core import CoreError, Daemon, find_build_dir
from proctor.envs.sql import SqlEnv, admin_dsn
from proctor.policy import VerifierPolicy
from proctor.tasks.sql import TASKS

try:
    find_build_dir()
    import psycopg
    psycopg.connect(admin_dsn().rpartition("/")[0] + "/postgres", connect_timeout=2).close()
    READY = True
except Exception:  # noqa: BLE001
    READY = False

pytestmark = pytest.mark.skipif(not READY, reason="needs the C++ core and a Postgres server (PROCTOR_PG_DSN)")


@pytest.fixture(scope="module")
def daemon():
    with Daemon(pool=2) as d:
        yield d


def ref_unqualified(task):
    return task.ref.replace("{s}.", "")


@pytest.mark.parametrize("pol", ["naive", "hardened"])
@pytest.mark.parametrize("task_id", sorted(TASKS))
def test_honest_query_rewarded(daemon, pol, task_id):
    policy = VerifierPolicy.naive() if pol == "naive" else VerifierPolicy.hardened()
    env = SqlEnv(daemon.client, policy, compute_oracle=True)
    obs, _ = env.reset(seed=5, options={"task_id": task_id})
    obs2, *_ = env.step({"type": "sql", "query": ref_unqualified(TASKS[task_id])})
    assert "rows)" in obs2["stdout"], obs2
    _, reward, term, _, info = env.step({"type": "submit", "query": ref_unqualified(TASKS[task_id])})
    env.close()
    assert term and reward == 1.0, info
    assert env.last_oracle is True


def test_sandbox_has_no_network_but_reaches_broker(daemon):
    env = SqlEnv(daemon.client, VerifierPolicy.hardened())
    env.reset(seed=1, options={"task_id": "never_ordered"})
    obs, *_ = env.step({"type": "python", "code": "import socket; socket.socket(socket.AF_INET)"})
    assert obs["denied"] == 1
    obs, *_ = env.step({"type": "bash", "cmd": "python3 /run/sql/psql.py 'select count(*) from customers'"})
    env.close()
    assert "40" in obs["stdout"]


def test_agent_role_is_readonly_when_hardened(daemon):
    env = SqlEnv(daemon.client, VerifierPolicy.hardened())
    env.reset(seed=1, options={"task_id": "never_ordered"})
    obs, *_ = env.step({"type": "sql", "query": "DELETE FROM orders"})
    env.close()
    assert "permission denied" in obs["stdout"]
