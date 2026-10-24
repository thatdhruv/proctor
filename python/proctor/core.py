"""Client for the C++ execution core (`proctord`) over its Unix-socket JSON-lines protocol."""
from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


class CoreError(RuntimeError):
    pass


def find_build_dir() -> Path:
    """Locate the directory holding proctord / proctor-init / proctor-run."""
    env = os.environ.get("PROCTOR_CORE_BUILD")
    candidates = [Path(env)] if env else []
    repo = Path(__file__).resolve().parents[2]
    candidates += [repo / "core" / "build", Path.home() / "pb"]
    for c in candidates:
        if (c / "proctord").exists():
            return c
    raise CoreError("proctord not built; run `make -C core` (set PROCTOR_CORE_BUILD to override)")


@dataclass
class ExecResult:
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    term_signal: int = 0
    timed_out: bool = False
    oom_killed: bool = False
    truncated: bool = False
    wall_ms: float = 0.0
    user_ms: float = 0.0
    sys_ms: float = 0.0
    max_rss_kb: int = 0
    error: str = ""
    denied: list[dict] = field(default_factory=list)

    @classmethod
    def from_json(cls, j: dict) -> "ExecResult":
        keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in j.items() if k in keys})

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error


class Sandbox:
    """A leased sandbox. Use as a context manager so it is always released."""

    def __init__(self, client: "CoreClient", info: dict):
        self._c = client
        self.id: str = info["sandbox_id"]
        self.source: str = info["source"]          # "warm" | "cold"
        self.acquire_ms: float = info["acquire_ms"]
        self.info = info
        self._released = False
        self._snapshotted = False  # a custom snapshot makes the sandbox unfit for recycling

    def exec(self, argv: Iterable[str], *, stdin: str = "", timeout_ms: int = 10_000,
             env: dict[str, str] | None = None, cwd: str = "/workspace",
             max_output: int = 1 << 20) -> ExecResult:
        r = self._c.call("exec", sandbox_id=self.id, argv=list(argv), stdin=stdin,
                         timeout_ms=timeout_ms, env=env or {}, cwd=cwd, max_output=max_output)
        return ExecResult.from_json(r)

    def bash(self, script: str, **kw) -> ExecResult:
        return self.exec(["/bin/bash", "-c", script], **kw)

    def write_file(self, path: str, data: str | bytes, mode: int = 0o644) -> None:
        b = data.encode() if isinstance(data, str) else data
        self._c.call("write_file", sandbox_id=self.id, path=path,
                     data_b64=base64.b64encode(b).decode(), mode=mode)

    def read_file(self, path: str) -> bytes:
        r = self._c.call("read_file", sandbox_id=self.id, path=path)
        return base64.b64decode(r["data_b64"])

    def snapshot(self) -> None:
        self._c.call("snapshot", sandbox_id=self.id)
        self._snapshotted = True

    def restore(self) -> float:
        return self._c.call("restore", sandbox_id=self.id)["restore_ms"]

    def denied(self) -> list[dict]:
        return self._c.call("denied", sandbox_id=self.id)["events"]

    def release(self, reuse: bool = True) -> bool:
        if self._released:
            return False
        self._released = True
        return self._c.call("release", sandbox_id=self.id, reuse=reuse and not self._snapshotted)["recycled"]

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.release()
        except CoreError:
            pass


class CoreClient:
    """Thread-safe client (one request in flight per client)."""

    def __init__(self, socket_path: str, timeout: float = 120.0):
        self.path = socket_path
        self._lock = threading.Lock()
        self._s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._s.settimeout(timeout)
        self._s.connect(socket_path)
        self._buf = b""

    def call(self, op: str, **kw: Any) -> dict:
        req = json.dumps({"op": op, **kw}).encode() + b"\n"
        with self._lock:
            self._s.sendall(req)
            while b"\n" not in self._buf:
                chunk = self._s.recv(1 << 20)
                if not chunk:
                    raise CoreError("proctord closed the connection")
                self._buf += chunk
            line, self._buf = self._buf.split(b"\n", 1)
        resp = json.loads(line)
        if not resp.get("ok", False):
            raise CoreError(resp.get("error", "unknown error"))
        return resp

    def acquire(self, *, cold: bool = False, limits: dict | None = None,
                binds: list[dict] | None = None) -> Sandbox:
        kw: dict[str, Any] = {"cold": cold}
        if limits:
            kw["limits"] = limits
        if binds:
            kw["binds"] = binds
        return Sandbox(self, self.call("acquire", **kw))

    def stats(self) -> dict:
        return self.call("stats")

    def close(self) -> None:
        self._s.close()


class Daemon:
    """Starts and owns a proctord process (for tests, benchmarks, local runs)."""

    def __init__(self, pool: int = 4, build_dir: Path | None = None, metrics_port: int = 0,
                 denied_log: str | None = None, extra_args: list[str] | None = None):
        self.build = build_dir or find_build_dir()
        self.dir = tempfile.mkdtemp(prefix="proctord-")
        self.socket_path = os.path.join(self.dir, "proctord.sock")
        args = [str(self.build / "proctord"), "--socket", self.socket_path, "--pool", str(pool),
                "--init", str(self.build / "proctor-init")]
        if metrics_port:
            args += ["--metrics-port", str(metrics_port)]
        if denied_log:
            args += ["--denied-log", denied_log]
        args += extra_args or []
        self.proc = subprocess.Popen(args, stderr=subprocess.PIPE, text=True)
        deadline = time.time() + 10
        while not os.path.exists(self.socket_path):
            if self.proc.poll() is not None or time.time() > deadline:
                raise CoreError("proctord failed to start: " + (self.proc.stderr.read() if self.proc.stderr else ""))
            time.sleep(0.01)
        self.client = CoreClient(self.socket_path)
        self.wait_pool(pool)

    def wait_pool(self, n: int, timeout: float = 30.0) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if self.client.stats()["pool"] >= n:
                return
            time.sleep(0.01)

    def stop(self) -> None:
        try:
            self.client.call("shutdown")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self) -> "Daemon":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
