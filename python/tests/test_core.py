import pytest

from proctor.core import CoreError, Daemon, find_build_dir

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


def test_warm_acquire_and_exec(daemon):
    with daemon.client.acquire() as sb:
        assert sb.source in ("warm", "cold")
        r = sb.exec(["/bin/echo", "hi"])
        assert r.ok and r.stdout == "hi\n"


def test_snapshot_restore_roundtrip(daemon):
    with daemon.client.acquire() as sb:
        sb.write_file("/workspace/a.txt", "one")
        sb.snapshot()
        sb.bash("echo two > /workspace/a.txt; echo x > /workspace/b.txt; mkdir /workspace/d")
        sb.restore()
        assert sb.read_file("/workspace/a.txt") == b"one"
        assert sb.bash("ls /workspace").stdout.split() == ["a.txt"]


def test_release_recycles_clean_sandbox(daemon):
    sb = daemon.client.acquire()
    sb.write_file("/workspace/leak.txt", "secret")
    assert sb.release() in (True, False)
    nxt = daemon.client.acquire()
    try:
        assert nxt.bash("ls /workspace").stdout.strip() == ""
    finally:
        nxt.release()


def test_tripped_sandbox_is_not_recycled(daemon):
    sb = daemon.client.acquire()
    r = sb.exec(["/usr/bin/python3", "-c", "import socket; socket.socket(socket.AF_INET)"])
    assert r.denied and r.denied[0]["syscall"] == "socket"
    assert sb.release() is False
