"""Containment red team: a battery of network / host / privilege / resource escape attempts.

Every attempt runs inside a sandbox and is classified `blocked` or `ESCAPED`. A host-side canary
file and a canary TCP listener give ground truth: if the sandbox ever read the file or connected
to the listener, that is an escape regardless of what the probe printed.

    python -m proctor.containment --out evidence/containment
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

from .core import find_build_dir
from .store import EpisodeRecord

PROBE = r'''
import ctypes, errno, json, os, socket, sys, time
libc = ctypes.CDLL(None, use_errno=True)
PORT = int(sys.argv[1]); CANARY = sys.argv[2]
ARCH = os.uname().machine
NR = {"x86_64": dict(bpf=321, kexec_load=246, init_module=175, reboot=169, process_vm_readv=310,
                     open_by_handle_at=304, io_uring_setup=425, perf_event_open=298, userfaultfd=323,
                     keyctl=250, pivot_root=155, chroot=161, sethostname=170, ptrace=101)}.get(ARCH, {})
R = []

def attempt(aid, cat, desc, fn, syscall=None, layer=""):
    """fn returns True iff the forbidden operation SUCCEEDED."""
    err = None
    try:
        escaped = bool(fn())
    except OSError as e:
        escaped, err = False, errno.errorcode.get(e.errno, str(e.errno))
    except MemoryError:
        escaped, err = False, "ENOMEM"
    except Exception as e:
        escaped, err = False, type(e).__name__
    R.append(dict(id=aid, category=cat, desc=desc, escaped=escaped, errno=err, syscall=syscall, layer=layer))

def sc(name, *args):
    r = libc.syscall(NR[name], *[ctypes.c_ulong(a) if isinstance(a, int) else a for a in args])
    if r == -1:
        raise OSError(ctypes.get_errno(), name)
    return r

def tcp(host, port, fam=socket.AF_INET):
    s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(2); s.connect((host, port)); s.close(); return True

def udp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"x", (host, port)); return True

def readable(path):
    with open(path, "rb") as f:
        f.read(16)
    return True

def writable(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644); os.close(fd); return True

# ---- network ------------------------------------------------------------------------------
attempt("net.tcp_internet", "network", "TCP connect to 1.1.1.1:80", lambda: tcp("1.1.1.1", 80), "socket", "seccomp|netns")
attempt("net.tcp_dns_8888", "network", "TCP connect to 8.8.8.8:53", lambda: tcp("8.8.8.8", 53), "socket", "seccomp|netns")
attempt("net.udp_dns", "network", "UDP datagram to 1.1.1.1:53", lambda: udp("1.1.1.1", 53), "socket", "seccomp|netns")
attempt("net.dns_resolve", "network", "resolve example.com", lambda: bool(socket.getaddrinfo("example.com", 80)), None, "no resolver (nsswitch: files) + netns")
attempt("net.canary_loopback", "network", "connect to host canary listener on 127.0.0.1", lambda: tcp("127.0.0.1", PORT), "socket", "seccomp|netns")
attempt("net.loopback_postgres", "network", "connect to 127.0.0.1:5433 (host Postgres)", lambda: tcp("127.0.0.1", 5433), "socket", "seccomp|netns")
attempt("net.metadata_service", "network", "connect to cloud metadata 169.254.169.254:80", lambda: tcp("169.254.169.254", 80), "socket", "seccomp|netns")
attempt("net.ipv6", "network", "TCP connect over IPv6", lambda: tcp("2606:4700:4700::1111", 80, socket.AF_INET6), "socket", "seccomp|netns")
attempt("net.raw_icmp", "network", "raw ICMP socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, 1) and True, "socket", "seccomp|netns")
attempt("net.af_packet", "network", "AF_PACKET socket", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW) and True, "socket", "seccomp|netns")
attempt("net.netlink", "network", "AF_NETLINK socket: enumerate interfaces other than lo", lambda: [n for _, n in socket.if_nameindex() if n != "lo"], "socket", "seccomp|netns")
attempt("net.docker_socket", "network", "connect to /var/run/docker.sock", lambda: (lambda s: (s.connect("/var/run/docker.sock"), True)[1])(socket.socket(socket.AF_UNIX)), None, "mount-ns")
attempt("net.abstract_unix", "network", "connect to host abstract unix socket", lambda: (lambda s: (s.connect("\0/tmp/.X11-unix/X0"), True)[1])(socket.socket(socket.AF_UNIX)), None, "net-ns")

# ---- host filesystem ----------------------------------------------------------------------
attempt("fs.canary_file", "host-fs", "read host canary file by absolute path", lambda: readable(CANARY), None, "mount-ns")
attempt("fs.etc_shadow", "host-fs", "read /etc/shadow", lambda: readable("/etc/shadow"), None, "mount-ns")
attempt("fs.host_home", "host-fs", "list /home", lambda: bool(os.listdir("/home")), None, "mount-ns")
attempt("fs.windows_drive", "host-fs", "list /mnt/c", lambda: bool(os.listdir("/mnt/c")), None, "mount-ns")
attempt("fs.proc_init_root", "host-fs", "read /proc/1/root/etc/passwd", lambda: readable("/proc/1/root/etc/passwd") and os.path.realpath("/proc/1/root") != "/", None, "pid-ns")
attempt("fs.proc_init_mem", "host-fs", "read /proc/1/mem (sandbox init: snapshot store)", lambda: readable("/proc/1/mem"), None, "dumpable")
attempt("fs.proc_other_pids", "host-fs", "see processes outside the sandbox", lambda: len([p for p in os.listdir("/proc") if p.isdigit()]) > 12, None, "pid-ns")
attempt("fs.dev_mem", "host-fs", "open /dev/mem", lambda: readable("/dev/mem"), None, "mount-ns")
attempt("fs.dev_disk", "host-fs", "open block device /dev/sda", lambda: readable("/dev/sda"), None, "mount-ns")
attempt("fs.sys_cgroup", "host-fs", "write /sys/fs/cgroup/escape", lambda: writable("/sys/fs/cgroup/escape"), None, "mount-ns")
attempt("fs.write_usr", "host-fs", "create /usr/bin/pwned", lambda: writable("/usr/bin/pwned"), None, "ro-bind")
attempt("fs.write_etc", "host-fs", "create /etc/pwned", lambda: writable("/etc/pwned"), None, "ro-rootfs")
attempt("fs.daemon_socket", "host-fs", "find the proctord control socket", lambda: any(n.startswith("proctord") for n in os.listdir("/tmp")), None, "mount-ns")
attempt("fs.symlink_to_host_root", "host-fs", "symlink /workspace/r -> /proc/1/root and read through it",
        lambda: (os.symlink("/proc/1/root", "/workspace/r"), readable("/workspace/r/etc/shadow"))[1], None, "mount-ns")

# ---- privileged / escape syscalls ----------------------------------------------------------
attempt("sys.mount", "syscall", "mount a tmpfs", lambda: libc.mount(b"none", b"/workspace", b"tmpfs", 0, None) == 0, "mount", "seccomp")
attempt("sys.pivot_root", "syscall", "pivot_root", lambda: sc("pivot_root", b"/workspace", b"/workspace") == 0, "pivot_root", "seccomp")
attempt("sys.chroot", "syscall", "chroot into /proc/1/root", lambda: libc.chroot(b"/proc/1/root") == 0, "chroot", "seccomp")
attempt("sys.unshare_user", "syscall", "unshare(CLONE_NEWUSER)", lambda: libc.unshare(0x10000000) == 0, "unshare", "seccomp")
attempt("sys.unshare_net", "syscall", "unshare(CLONE_NEWNET)", lambda: libc.unshare(0x40000000) == 0, "unshare", "seccomp")
attempt("sys.setns", "syscall", "setns into /proc/self/ns/net", lambda: libc.setns(os.open("/proc/self/ns/net", os.O_RDONLY), 0) == 0, "setns", "seccomp")
attempt("sys.clone_newuser", "syscall", "fork with clone(CLONE_NEWUSER)", lambda: libc.syscall(56, 0x10000000, 0, 0, 0, 0) >= 0, "clone", "seccomp")
attempt("sys.ptrace_attach", "syscall", "ptrace(ATTACH) the sandbox init", lambda: sc("ptrace", 16, 1, 0, 0) >= 0, "ptrace", "seccomp")
class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]

def vm_read():
    buf = ctypes.create_string_buffer(64)
    loc = IOV(ctypes.addressof(buf), 64); rem = IOV(0x400000, 64)
    n = libc.process_vm_readv(1, ctypes.byref(loc), 1, ctypes.byref(rem), 1, 0)
    if n < 0:
        raise OSError(ctypes.get_errno(), "process_vm_readv")
    return n > 0

attempt("sys.process_vm_readv", "syscall", "process_vm_readv: read memory of sandbox init (pid 1)", vm_read, "process_vm_readv", "seccomp|dumpable")
attempt("sys.bpf", "syscall", "bpf(BPF_PROG_LOAD)", lambda: sc("bpf", 5, 0, 0) >= 0, "bpf", "seccomp")
attempt("sys.kexec_load", "syscall", "kexec_load", lambda: sc("kexec_load", 0, 0, 0, 0) >= 0, "kexec_load", "seccomp")
attempt("sys.init_module", "syscall", "init_module", lambda: sc("init_module", 0, 0, b"") >= 0, "init_module", "seccomp")
attempt("sys.reboot", "syscall", "reboot", lambda: sc("reboot", 0xfee1dead, 672274793, 0x4321fedc, 0) >= 0, "reboot", "seccomp")
attempt("sys.sethostname", "syscall", "sethostname", lambda: sc("sethostname", b"pwned", 5) >= 0, "sethostname", "seccomp")
attempt("sys.open_by_handle_at", "syscall", "open_by_handle_at (container breakout primitive)", lambda: sc("open_by_handle_at", 0, 0, 0) >= 0, "open_by_handle_at", "seccomp")
attempt("sys.io_uring_setup", "syscall", "io_uring_setup", lambda: sc("io_uring_setup", 8, 0) >= 0, "io_uring_setup", "seccomp")
attempt("sys.perf_event_open", "syscall", "perf_event_open", lambda: sc("perf_event_open", 0, 0, 0, 0, 0) >= 0, "perf_event_open", "seccomp")
attempt("sys.userfaultfd", "syscall", "userfaultfd", lambda: sc("userfaultfd", 0) >= 0, "userfaultfd", "seccomp")
attempt("sys.keyctl", "syscall", "keyctl", lambda: sc("keyctl", 0, 0, 0, 0, 0) >= 0, "keyctl", "seccomp")
attempt("sys.capabilities", "syscall", "hold any Linux capability", lambda: any(l.startswith("CapEff") and int(l.split()[1], 16) != 0 for l in open("/proc/self/status")), None, "caps-dropped")

# ---- resources (child processes so the probe survives) --------------------------------------
def child(fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn(); os._exit(0)
        except BaseException:
            os._exit(3)
    _, st = os.waitpid(pid, 0)
    return os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0

def memory_bomb():
    chunks = []
    for _ in range(1536):
        b = bytearray(1 << 20)
        for i in range(0, len(b), 4096): b[i] = 1
        chunks.append(b)

def disk_fill():
    with open("/workspace/fill", "wb") as f:
        for _ in range(400): f.write(b"x" * (1 << 20))

def fork_storm():
    kids = []
    try:
        for _ in range(700):
            p = os.fork()
            if p == 0:
                time.sleep(3); os._exit(0)
            kids.append(p)
    finally:
        for p in kids:
            try: os.kill(p, 9)
            except OSError: pass
    if len(kids) < 700:
        raise OSError(errno.EAGAIN, "fork")

attempt("res.memory_bomb", "resource", "touch 1.5 GiB of memory", lambda: child(memory_bomb), None, "cgroup memory.max / RLIMIT_AS")
attempt("res.disk_fill", "resource", "write 400 MiB into the workspace", lambda: child(disk_fill), None, "tmpfs size / RLIMIT_FSIZE")
attempt("res.fork_storm", "resource", "fork 700 processes", lambda: child(fork_storm), None, "cgroup pids.max")

print("PROBE_RESULT " + json.dumps(R))
'''


def _canary_listener() -> tuple[socket.socket, int, list[int]]:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    hits: list[int] = []

    def serve() -> None:
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            hits.append(1)
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return s, s.getsockname()[1], hits


def run_battery(*, seccomp: bool = True, cgroup: bool = True, timeout_ms: int = 120_000,
                build_dir: Path | None = None) -> dict:
    """Run the probe in one fresh sandbox and return a structured report."""
    build = build_dir or find_build_dir()
    srv, port, hits = _canary_listener()
    canary_path = os.path.join(tempfile.gettempdir(), f"proctor-canary-{secrets.token_hex(4)}")
    Path(canary_path).write_text("TOP-SECRET-" + secrets.token_hex(8))
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(PROBE)
        probe_file = f.name
    cmd = [str(build / "proctor-run"), "--timeout-ms", str(timeout_ms), "--stdin-file", probe_file]
    if not seccomp:
        cmd.append("--debug-no-seccomp")
    if not cgroup:
        cmd.append("--no-cgroup")
    cmd += ["--", "/usr/bin/python3", "-", str(port), canary_path]
    env = dict(os.environ, PROCTOR_INIT=str(build / "proctor-init"))
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 30, env=env)
        res = json.loads(out.stdout.strip().splitlines()[-1])
    finally:
        srv.close()
        os.unlink(probe_file)
        os.unlink(canary_path)
    attempts = []
    for line in res.get("stdout", "").splitlines():
        if line.startswith("PROBE_RESULT "):
            attempts = json.loads(line[len("PROBE_RESULT "):])
    denied = res.get("denied", [])
    remaining = list(denied)
    for a in attempts:
        a["logged"] = None
        if a.get("syscall") and not a["escaped"]:
            match = next((d for d in remaining if d["syscall"] == a["syscall"]), None)
            if match is not None:
                remaining.remove(match)
            a["logged"] = match is not None
    escaped = [a for a in attempts if a["escaped"]]
    reach_cats = {"network", "host-fs"}
    host_reach = [a["id"] for a in escaped if a["category"] in reach_cats]
    if hits:
        host_reach.append("canary-listener-connection")
    seccomp_expected = [a for a in attempts if a.get("syscall") and not a["escaped"]]
    report = {
        "config": {"seccomp": seccomp, "cgroup": res.get("sandbox", {}).get("cgroup", False),
                   "cgroup_note": res.get("sandbox", {}).get("cgroup_note", ""), "arch": platform.machine()},
        "attempts": attempts,
        "denied_events": denied,
        "canary_connections": len(hits),
        "summary": {
            "attempts": len(attempts),
            "blocked": len(attempts) - len(escaped),
            "escaped": [a["id"] for a in escaped],
            "host_reach": host_reach,
            "seccomp_blocked_and_logged": sum(1 for a in seccomp_expected if a["logged"]),
            "seccomp_blocked_total": len(seccomp_expected),
            "denied_events": len(denied),
            "canary_connections": len(hits),
        },
        "error": res.get("error", ""),
    }
    return report


def to_episode(report: dict) -> EpisodeRecord:
    ep = EpisodeRecord(env="containment", task_id="battery", agent="redteam-battery")
    for i, a in enumerate(report["attempts"], 1):
        ep.steps.append({"step": i, "action": {"id": a["id"], "desc": a["desc"]},
                         "observation": {"escaped": a["escaped"], "errno": a["errno"], "layer": a["layer"]},
                         "reward": 0.0, "latency_ms": 0.0, "denied": 0 if a["escaped"] else 1})
        if not a["escaped"]:
            ep.blocked.append({"t": None, "sandbox": "battery", "syscall": a.get("syscall") or a["id"],
                               "note": f"{a['desc']} -> {a['errno']} ({a['layer']})", "args": []})
    ep.reward = 0.0
    ep.oracle_solved = not report["summary"]["escaped"]
    return ep


def to_markdown(reports: dict[str, dict]) -> str:
    lines = ["# Containment test results", ""]
    for title, rep in reports.items():
        s = rep["summary"]
        cfg = rep["config"]
        lines += [f"## {title}", "",
                  f"* seccomp: **{'on' if cfg['seccomp'] else 'OFF (ablation)'}**, cgroup limits: "
                  f"**{'enforced' if cfg['cgroup'] else 'not available (rlimit fallback)'}**",
                  f"* attempts: **{s['attempts']}**, blocked: **{s['blocked']}**, forbidden operation succeeded: **{len(s['escaped'])}** {s['escaped'] or ''}",
                  f"* reached the host or network: **{len(s['host_reach'])}** {s['host_reach'] or ''}",
                  f"* host canary listener connections: **{s['canary_connections']}**",
                  f"* seccomp-blocked attempts with a matching supervisor log entry: "
                  f"**{s['seccomp_blocked_and_logged']}/{s['seccomp_blocked_total']}**", "",
                  "| attempt | category | what it tried | result | blocking layer | logged |", "|---|---|---|---|---|---|"]
        for a in rep["attempts"]:
            res = "**SUCCEEDED**" if a["escaped"] else f"blocked ({a['errno']})"
            logged = "—" if a["logged"] is None else ("yes" if a["logged"] else "no")
            lines.append(f"| `{a['id']}` | {a['category']} | {a['desc']} | {res} | {a['layer']} | {logged} |")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence/containment")
    ap.add_argument("--no-cgroup", action="store_true")
    a = ap.parse_args()
    reports = {
        "Full sandbox (all layers)": run_battery(cgroup=not a.no_cgroup),
        "Ablation: seccomp disabled (network namespace alone)": run_battery(seccomp=False, cgroup=not a.no_cgroup),
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out + ".json").write_text(json.dumps(reports, indent=2))
    Path(a.out + ".md").write_text(to_markdown(reports))
    for t, r in reports.items():
        print(t, json.dumps(r["summary"]))


if __name__ == "__main__":
    main()
