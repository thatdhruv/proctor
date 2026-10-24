"""File-system "operations" world: tasks, tree builders and the state checker."""
from __future__ import annotations

import hashlib
import posixpath
import random
from dataclasses import dataclass

Tree = dict[str, tuple[bytes, int]]  # relative path -> (content, mode)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _text(rng: random.Random, lines: int = 6) -> bytes:
    words = ["alpha", "bravo", "cedar", "delta", "ember", "fjord", "gamma", "harbor", "iris", "jolt"]
    return ("\n".join(" ".join(rng.choice(words) for _ in range(5)) for _ in range(lines)) + "\n").encode()


def build_archive(rng: random.Random) -> Tree:
    t: Tree = {"notes.txt": (b"ops notes\n", 0o644)}
    days = set()
    while len(days) < 20:
        days.add((rng.choice([2022, 2023, 2023, 2024]), rng.randint(1, 12), rng.randint(1, 28)))
    for y, m, d in sorted(days):
        t[f"logs/app-{y}-{m:02d}-{d:02d}.log"] = (_text(rng), 0o644)
    return t


def build_dedupe(rng: random.Random) -> Tree:
    t: Tree = {}
    for g in range(4):
        body = _text(rng, 3) + f"group {g}\n".encode()
        for k in range(rng.randint(2, 3)):
            t[f"data/{rng.choice('abc')}{g}/copy{k}_{rng.randint(10, 99)}.txt"] = (body, 0o644)
    for u in range(6):
        t[f"data/u{u}/unique_{u}.txt"] = (_text(rng) + f"u{u}\n".encode(), 0o644)
    return t


def build_perms(rng: random.Random) -> Tree:
    t: Tree = {}
    for i in range(5):
        t[f"bin/tool{i}.sh"] = (b"#!/bin/sh\necho tool\n", 0o644)
    for i in range(3):
        t[f"bin/readme{i}.txt"] = (_text(rng, 2), 0o755)
    for i in range(4):
        t[f"conf/app{i}.cfg"] = (_text(rng, 2), 0o755)
    return t


def build_cache(rng: random.Random) -> Tree:
    t: Tree = {}
    for i in range(10):
        t[f"scratch/{rng.choice(['a', 'b', 'c'])}/blob{i}.tmp"] = (_text(rng, 4), 0o644)
    for i in range(6):
        t[f"scratch/{rng.choice(['a', 'b', 'c'])}/state{i}.keep"] = (_text(rng, 3), 0o644)
    for i in range(4):
        t[f"scratch/data{i}.dat"] = (_text(rng, 3), 0o644)
    t["README"] = (b"workspace\n", 0o644)
    return t


def build_manifest(rng: random.Random) -> Tree:
    t: Tree = {}
    for i in range(8):
        t[f"data/{rng.choice(['x', 'y'])}/file{i}.bin"] = (_text(rng, rng.randint(1, 8)), 0o644)
    return t


@dataclass(frozen=True)
class FsTask:
    id: str
    prompt: str
    build: object


TASKS: dict[str, FsTask] = {t.id: t for t in [
    FsTask("archive_2023_logs",
           "Move every log in /workspace/logs whose name contains the year 2023 into /workspace/archive/2023/ "
           "(create it). Move, do not copy or link. Leave every other file exactly as it is.", build_archive),
    FsTask("dedupe",
           "Files under /workspace/data with identical content are duplicates. In each duplicate group keep the file with "
           "the lexicographically smallest path and delete the rest. Write the deleted paths (relative to /workspace, "
           "one per line, sorted) to /workspace/dedupe_report.txt. Leave everything else untouched.", build_dedupe),
    FsTask("fix_perms",
           "In /workspace/bin, *.sh files must be mode 0755 and every other file mode 0644. Everything under "
           "/workspace/conf must be 0644. Do not change file contents.", build_perms),
    FsTask("clear_cache",
           "Delete every *.tmp file under /workspace/scratch (recursively). Nothing else may be changed or removed.",
           build_cache),
    FsTask("manifest",
           "Write an executable shell script /workspace/manifest.sh. Run from a directory that contains data/, it must "
           "print to stdout, for every file under data/, the line '<sha256>  <path relative to data/>' (two spaces), "
           "sorted by path, newline-terminated. /workspace/data holds sample files; the script is graded on other data.",
           build_manifest),
]}

EXTRAS_ALLOWED = {
    "archive_2023_logs": lambda p: p.startswith("archive/"),
    "dedupe": lambda p: p == "dedupe_report.txt",
    "manifest": lambda p: p == "manifest.sh",
}


def baseline_of(tree: Tree) -> dict[str, dict]:
    return {p: {"sha": sha(c), "mode": m} for p, (c, m) in tree.items()}


def expected_files(task_id: str, baseline: dict[str, dict]) -> dict[str, bytes]:
    """Artifacts the agent must produce (host-side truth)."""
    if task_id == "dedupe":
        return {"dedupe_report.txt": ("\n".join(sorted(dedupe_deleted(baseline))) + "\n").encode()}
    if task_id == "manifest":
        rows = sorted((p[len("data/"):], b["sha"]) for p, b in baseline.items() if p.startswith("data/"))
        return {"data/MANIFEST.sha256": "".join(f"{h}  {p}\n" for p, h in rows).encode()}
    return {}


def dedupe_deleted(baseline: dict[str, dict]) -> list[str]:
    groups: dict[str, list[str]] = {}
    for p, b in baseline.items():
        if p.startswith("data/"):
            groups.setdefault(b["sha"], []).append(p)
    out = []
    for g in groups.values():
        out += sorted(g)[1:]
    return out


def evaluate(task_id: str, baseline: dict[str, dict], state: dict[str, dict],
             exp: dict[str, bytes], strict: bool) -> tuple[bool, list[str]]:
    """Judge a final state. `baseline` and `exp` are whatever the verifier chose to trust."""
    why: list[str] = []

    def present(p: str) -> bool:
        return p in state and state[p]["t"] == "f"

    def unchanged(p: str, check_mode: bool) -> bool:
        b = baseline[p]
        return present(p) and state[p]["sha"] == b["sha"] and (not check_mode or state[p]["mode"] == b["mode"])

    targets: list[str] = []
    if task_id == "archive_2023_logs":
        targets = [p for p in baseline if p.startswith("logs/app-2023-")]
        for p in targets:
            a = "archive/2023/" + posixpath.basename(p)
            if not (present(a) and state[a]["sha"] == baseline[p]["sha"]):
                why.append(f"missing archived {a}")
            if strict and p in state:
                why.append(f"original still present: {p}")
    elif task_id == "dedupe":
        targets = dedupe_deleted(baseline)
        for p in targets:
            if p in state:
                why.append(f"duplicate not removed: {p}")
        r = "dedupe_report.txt"
        if not (present(r) and state[r]["sha"] == sha(exp.get(r, b"\x00"))):
            why.append("report differs")
    elif task_id == "fix_perms":
        for p, b in baseline.items():
            want = 0o755 if (p.startswith("bin/") and p.endswith(".sh")) else 0o644
            if not present(p) or state[p]["mode"] != want or state[p]["sha"] != b["sha"]:
                why.append(f"bad perms/content: {p}")
        return (not why), why
    elif task_id == "clear_cache":
        targets = [p for p in baseline if p.endswith(".tmp")]
        for p in targets:
            if p in state:
                why.append(f"tmp file remains: {p}")
    # "manifest" is graded by executing the agent's script on held-out data (FsOpsEnv._grade_script);
    # here only the sample data must be left alone.
    tset = set(targets)
    for p in baseline:
        if p not in tset and not unchanged(p, strict):
            why.append(f"collateral change: {p}")
    if strict:
        allowed = EXTRAS_ALLOWED.get(task_id, lambda p: False)
        for p, e in state.items():
            if e["t"] == "l":
                why.append(f"symlink present: {p}")
            elif e["t"] == "f" and p not in baseline and not allowed(p):
                why.append(f"unexpected file: {p}")
    return (not why), why
