#!/usr/bin/env python3
"""Integration tests for the C++ core. Usage: run_tests.py BUILD_DIR"""
import json
import os
import subprocess
import sys

BUILD = sys.argv[1] if len(sys.argv) > 1 else "build"
RUN = os.path.join(BUILD, "proctor-run")
FAILS = []


def run(*cmd, timeout_ms=5000, extra=()):
    out = subprocess.run([RUN, "--timeout-ms", str(timeout_ms), *extra, "--", *cmd],
                         capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout)


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        FAILS.append(name)


PY = "/usr/bin/python3"

r = run("/bin/echo", "hello")
check("echo runs", r["stdout"] == "hello\n" and r["exit_code"] == 0, r)

r = run("/bin/sh", "-c", "cat /etc/hostname; id -u; ls /home 2>&1; ls /root 2>&1")
check("host dirs are not visible", "No such file" in r["stdout"], r["stdout"])

r = run(PY, "-c", "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
check("AF_INET socket() denied", r["exit_code"] != 0 and "Operation not permitted" in r["stderr"], r)
check("AF_INET socket() logged", any(e["syscall"] == "socket" and "AF_INET" in e["note"] for e in r["denied"]), r["denied"])

r = run(PY, "-c", "import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('unix ok')")
check("AF_UNIX socket() allowed", "unix ok" in r["stdout"], r)

r = run("/bin/sh", "-c", "echo x > /etc/passwd")
check("rootfs is read-only", r["exit_code"] != 0, r)

r = run(PY, "-c",
        "import ctypes,os\n"
        "libc=ctypes.CDLL(None,use_errno=True)\n"
        "r=libc.mount(b'none',b'/workspace',b'tmpfs',0,None)\n"
        "print(r, os.strerror(ctypes.get_errno()))")
check("mount() denied", "Operation not permitted" in r["stdout"], r)
check("mount() logged", any(e["syscall"] == "mount" for e in r["denied"]), r["denied"])

r = run(PY, "-c",
        "import ctypes,os\n"
        "libc=ctypes.CDLL(None,use_errno=True)\n"
        "r=libc.unshare(0x10000000)\n"
        "print(r, os.strerror(ctypes.get_errno()))")
check("unshare(CLONE_NEWUSER) denied+logged", "Operation not permitted" in r["stdout"] and any(e["syscall"] == "unshare" for e in r["denied"]), r)

r = run(PY, "-c",
        "import ctypes,os\n"
        "libc=ctypes.CDLL(None,use_errno=True)\n"
        "r=libc.ptrace(0,0,0,0)\n"
        "print(r, os.strerror(ctypes.get_errno()))")
check("ptrace denied+logged", any(e["syscall"] == "ptrace" for e in r["denied"]), r)

r = run("/bin/sh", "-c", "cat /proc/1/environ 2>&1; cat /proc/1/mem 2>&1 | head -c 50")
check("init is not inspectable", "Permission denied" in r["stdout"] or "denied" in r["stdout"].lower(), r["stdout"])

r = run("/bin/sh", "-c", "while :; do :; done", timeout_ms=300)
check("wall-clock timeout kills", r["timed_out"] is True, r)

r = run("/bin/sh", "-c", "yes | head -c 5000000", extra=())
check("output cap truncates", r["truncated"] is True and len(r["stdout"]) <= (1 << 20), len(r["stdout"]))

r = run("/bin/sh", "-c", "(sleep 30 &) ; echo done", timeout_ms=3000)
check("background procs do not outlive exec", r["wall_ms"] < 1500 and "done" in r["stdout"], r)

# Per-sandbox fork bomb must not take the host down (cgroup pids.max, or the wall-clock kill).
r = run("/bin/sh", "-c", ":(){ :|:& };:", timeout_ms=1500)
check("fork bomb contained", r["wall_ms"] < 6000, r["wall_ms"])

print(f"\n{len(FAILS)} failure(s)")
sys.exit(1 if FAILS else 0)
