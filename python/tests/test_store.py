import pytest

from proctor.core import CoreError, Daemon, find_build_dir
from proctor.envs.coding import CodingEnv
from proctor.envs.sql import admin_dsn
from proctor.policy import VerifierPolicy
from proctor.store import PostgresStore

try:
    find_build_dir()
    import psycopg
    DSN = admin_dsn().rpartition("/")[0] + "/postgres"
    psycopg.connect(DSN, connect_timeout=2).close()
    READY = True
except Exception:  # noqa: BLE001
    READY = False

pytestmark = pytest.mark.skipif(not READY, reason="needs the C++ core and Postgres")


def test_episode_roundtrip_in_postgres():
    store = PostgresStore(DSN)
    with Daemon(pool=1) as d:
        env = CodingEnv(d.client, VerifierPolicy.naive(), store=store, compute_oracle=True, agent_name="t", round_no=7)
        env.reset(seed=1, options={"task_id": "is_balanced"})
        env.step({"type": "bash", "cmd": "python3 -c 'import socket; socket.socket(socket.AF_INET)'"})
        env.step({"type": "submit"})
        env.close()
    ep = store.conn.execute("SELECT env, task_id, round, steps, reward, oracle_solved, cheated FROM episodes "
                            "WHERE agent='t' AND round=7 ORDER BY started_at DESC LIMIT 1").fetchone()
    assert ep[:4] == ("coding", "is_balanced", 7, 2) and ep[4] == 0 and ep[5] is False and ep[6] is False
    eid = store.conn.execute("SELECT id FROM episodes WHERE agent='t' AND round=7 ORDER BY started_at DESC LIMIT 1").fetchone()[0]
    assert store.conn.execute("SELECT count(*) FROM trajectories WHERE episode_id=%s", (eid,)).fetchone()[0] == 2
    assert store.conn.execute("SELECT count(*) FROM blocked_events WHERE episode_id=%s AND syscall='socket'", (eid,)).fetchone()[0] == 1
    assert store.conn.execute("SELECT count(*) FROM rewards WHERE episode_id=%s", (eid,)).fetchone()[0] == 2
    store.conn.execute("DELETE FROM episodes WHERE agent='t'")
    store.close()
