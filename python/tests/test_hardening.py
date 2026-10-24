"""The red team must be real (works on the naive verifier) and the end state must be sound."""
import pytest

from proctor.agents.exploits import EXPLOITS
from proctor.core import CoreError, Daemon, find_build_dir
from proctor.envs.sql import admin_dsn
from proctor.hardening.fixer import CATALOGUE, ScriptedFixer
from proctor.hardening.loop import hardening_loop, honest_check, run_exploit
from proctor.policy import VerifierPolicy
from proctor.store import MemoryStore

try:
    find_build_dir()
    import psycopg
    psycopg.connect(admin_dsn().rpartition("/")[0] + "/postgres", connect_timeout=2).close()
    READY = True
except Exception:  # noqa: BLE001
    READY = False

pytestmark = pytest.mark.skipif(not READY, reason="needs the C++ core and Postgres")

REAL = [e for e in EXPLOITS if not e.id.startswith("esc.")]


@pytest.fixture(scope="module")
def daemon():
    with Daemon(pool=4) as d:
        yield d


@pytest.mark.parametrize("ex", REAL, ids=lambda e: e.id)
def test_exploit_works_against_naive_verifier(daemon, ex):
    stat = run_exploit(daemon.client, ex, VerifierPolicy.naive(), 0, [1], MemoryStore())
    assert stat.cheats == stat.attempts > 0, stat


@pytest.mark.parametrize("ex", EXPLOITS, ids=lambda e: e.id)
def test_nothing_works_against_hardened_verifier(daemon, ex):
    stat = run_exploit(daemon.client, ex, VerifierPolicy.hardened(), 9, [1], MemoryStore())
    assert stat.cheats == 0 and stat.escapes == 0, stat


def test_sandbox_escape_attempts_are_blocked_and_logged(daemon):
    esc = next(e for e in EXPLOITS if e.id == "esc.coding")
    store = MemoryStore()
    stat = run_exploit(daemon.client, esc, VerifierPolicy.naive(), 0, [1], store)
    assert stat.escapes == 0 and stat.blocked_events > 0
    assert all(ep.blocked for ep in store.episodes)


def test_hardening_never_breaks_honest_solutions(daemon):
    got = honest_check(daemon.client, VerifierPolicy.hardened(), 0, MemoryStore(), [2])
    assert all(ok == total for ok, total in got.values()), got


def test_loop_converges_to_zero_cheating(daemon):
    reps = hardening_loop(daemon.client, MemoryStore(), fixer=ScriptedFixer(budget=5), seeds=[1],
                          max_rounds=8, progress=lambda *_: None)
    assert reps[0].overall_rate() > 0.5
    assert reps[-1].overall_rate() == 0.0
    rates = [r.overall_rate() for r in reps]
    assert rates == sorted(rates, reverse=True)  # monotone: patches never reintroduce cheating


def test_catalogue_covers_every_exploit():
    assert {e.id for e in REAL} <= set(CATALOGUE)
    for flags in CATALOGUE.values():
        for f in flags:
            assert f in VerifierPolicy.flag_names()
