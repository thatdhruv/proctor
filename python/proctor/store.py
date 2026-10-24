"""Episode / trajectory / reward storage. Postgres in production, in-memory for tests."""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

SCHEMA = """
CREATE TABLE IF NOT EXISTS episodes (
  id            uuid PRIMARY KEY,
  env           text NOT NULL,
  task_id       text NOT NULL,
  seed          integer,
  agent         text,
  round         integer,
  policy        jsonb,
  steps         integer,
  reward        real,
  oracle_solved boolean,
  cheated       boolean,
  exploit_id    text,
  exploit_type  text,
  trace_id      text,
  started_at    timestamptz DEFAULT now(),
  ended_at      timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS trajectories (
  episode_id uuid REFERENCES episodes(id) ON DELETE CASCADE,
  step       integer,
  action     jsonb,
  observation jsonb,
  reward     real,
  latency_ms real,
  denied     integer DEFAULT 0,
  PRIMARY KEY (episode_id, step)
);
CREATE TABLE IF NOT EXISTS rewards (
  episode_id uuid REFERENCES episodes(id) ON DELETE CASCADE,
  source     text,           -- 'verifier' | 'oracle'
  value      real,
  detail     jsonb,
  PRIMARY KEY (episode_id, source)
);
CREATE TABLE IF NOT EXISTS blocked_events (
  id         bigserial PRIMARY KEY,
  episode_id uuid REFERENCES episodes(id) ON DELETE CASCADE,
  ts         double precision,
  sandbox    text,
  syscall    text,
  note       text,
  args       jsonb
);
CREATE INDEX IF NOT EXISTS episodes_round_idx ON episodes(round, exploit_type);
"""


@dataclass
class EpisodeRecord:
    env: str
    task_id: str
    seed: int | None = None
    agent: str = ""
    round: int | None = None
    policy: dict = field(default_factory=dict)
    exploit_id: str | None = None
    exploit_type: str | None = None
    trace_id: str | None = None
    reward: float = 0.0
    oracle_solved: bool | None = None
    reward_detail: dict = field(default_factory=dict)
    oracle_detail: dict = field(default_factory=dict)
    steps: list[dict] = field(default_factory=list)
    blocked: list[dict] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def cheated(self) -> bool | None:
        if self.oracle_solved is None:
            return None
        return self.reward > 0 and not self.oracle_solved


class Store(Protocol):
    def write_episode(self, ep: EpisodeRecord) -> None: ...


class NullStore:
    def write_episode(self, ep: EpisodeRecord) -> None:
        pass


class MemoryStore:
    def __init__(self) -> None:
        self.episodes: list[EpisodeRecord] = []

    def write_episode(self, ep: EpisodeRecord) -> None:
        self.episodes.append(ep)


class PostgresStore:
    def __init__(self, dsn: str):
        import psycopg
        self.conn = psycopg.connect(dsn, autocommit=True)
        self.conn.execute(SCHEMA)
        self._lock = threading.Lock()  # one connection shared by rollout worker threads

    def write_episode(self, ep: EpisodeRecord) -> None:
        with self._lock:
            self._write(ep)

    def _write(self, ep: EpisodeRecord) -> None:
        from psycopg.types.json import Jsonb
        with self.conn.transaction():
            self.conn.execute(
                "INSERT INTO episodes (id, env, task_id, seed, agent, round, policy, steps, reward,"
                " oracle_solved, cheated, exploit_id, exploit_type, trace_id)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (ep.id, ep.env, ep.task_id, ep.seed, ep.agent, ep.round, Jsonb(ep.policy), len(ep.steps),
                 ep.reward, ep.oracle_solved, ep.cheated, ep.exploit_id, ep.exploit_type, ep.trace_id))
            with self.conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO trajectories (episode_id, step, action, observation, reward, latency_ms, denied)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    [(ep.id, s["step"], Jsonb(s["action"]), Jsonb(s["observation"]), s["reward"],
                      s["latency_ms"], s.get("denied", 0)) for s in ep.steps])
                cur.execute("INSERT INTO rewards VALUES (%s,'verifier',%s,%s)",
                            (ep.id, ep.reward, Jsonb(ep.reward_detail)))
                if ep.oracle_solved is not None:
                    cur.execute("INSERT INTO rewards VALUES (%s,'oracle',%s,%s)",
                                (ep.id, 1.0 if ep.oracle_solved else 0.0, Jsonb(ep.oracle_detail)))
                if ep.blocked:
                    cur.executemany(
                        "INSERT INTO blocked_events (episode_id, ts, sandbox, syscall, note, args)"
                        " VALUES (%s,%s,%s,%s,%s,%s)",
                        [(ep.id, b.get("t"), b.get("sandbox"), b.get("syscall"), b.get("note"),
                          Jsonb(b.get("args", []))) for b in ep.blocked])

    def close(self) -> None:
        self.conn.close()


def jsonable(x: Any) -> Any:
    return json.loads(json.dumps(x, default=str))
