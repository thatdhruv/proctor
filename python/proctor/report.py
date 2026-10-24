"""Render the README figures from the JSON in evidence/.   python -m proctor.report [--evidence evidence] [--out docs/images]"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

# Validated reference palette (categorical slots 1-3, light surface) and ink tokens.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.edgecolor": GRID, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "font.size": 10.5, "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "font.family": "DejaVu Sans",
})


def load(p: Path):
    return json.loads(p.read_text())


def fmt_ms(v: float) -> str:
    return f"{v * 1000:.0f} µs" if v < 1 else f"{v:.1f} ms"


def startup(ev: Path, out: Path) -> None:
    d = load(ev / "core_bench_docker.json")["startup"]
    rows = [("Cold: create sandbox (clone + rootfs + seccomp)", d["cold_acquire_ms"]),
            ("Cold: until first command returns", d["cold_to_first_result_ms"]),
            ("Warm: lease a pooled sandbox", d["warm_acquire_ms"]),
            ("Warm: until first command returns", d["warm_to_first_result_ms"]),
            ("Snapshot-restore (reset workspace in place)", d["snapshot_restore_ms"])]
    colors = [ORANGE, ORANGE, BLUE, BLUE, AQUA]
    fig, ax = plt.subplots(figsize=(9.2, 3.9))
    y = np.arange(len(rows))[::-1]
    for yi, (label, s), c in zip(y, rows, colors):
        ax.barh(yi, s["p50"], color=c, height=0.55, zorder=3)
        ax.plot([s["p99"]], [yi], marker="|", color=INK, markersize=14, zorder=4)
        ax.text(s["p99"] * 1.25, yi, f"p50 {fmt_ms(s['p50'])}   p99 {fmt_ms(s['p99'])}", va="center", color=INK, fontsize=9.5)
    ax.set_yticks(y, [r[0] for r in rows])
    ax.set_xscale("log")
    ax.set_xlim(0.05, 120)
    ax.set_xlabel("milliseconds (log scale);  bar = p50, tick = p99;  n=300 each")
    ax.set_title("Sandbox startup latency: cold vs warm (Docker, cgroups on)", loc="right")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(out / "startup_latency.png", dpi=160)
    plt.close(fig)


def throughput(ev: Path, out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 3.9), sharey=True)
    for ax, (name, title) in zip(axes, [("core_bench_docker.json", "Docker (cgroups enforced)"),
                                         ("core_bench_wsl.json", "WSL2 native (rlimit fallback)")]):
        t = load(ev / name)["throughput"]
        for mode, c in (("warm", BLUE), ("cold", ORANGE)):
            pts = [(r["workers"], r["steps_per_sec"]) for r in t if r["mode"] == mode]
            xs, ys = zip(*pts)
            ax.plot(xs, ys, color=c, lw=2.2, marker="o", ms=5, zorder=3)
            ax.text(xs[-1] * 1.07, ys[-1], f"{mode}\n{ys[-1]:,.0f}/s", color=INK, va="center", fontsize=9.5)
            if mode == "warm":
                i = int(np.argmax(ys))
                ax.annotate(f"peak {ys[i]:,.0f}/s", (xs[i], ys[i]), textcoords="offset points", xytext=(0, 9),
                            ha="center", color=INK2, fontsize=8.5)
        ax.set_xscale("log", base=2)
        ax.set_xticks([1, 2, 4, 8, 16, 32], ["1", "2", "4", "8", "16", "32"])
        ax.set_xlim(0.8, 60)
        ax.set_ylim(0, 2700)
        ax.set_title(title)
        ax.set_xlabel("parallel clients")
    axes[0].set_ylabel("sandboxed commands / second")
    fig.suptitle("Core throughput: lease a sandbox, run a command, release (per second)", x=0.01, ha="left",
                 fontweight="bold", fontsize=12.5)
    fig.tight_layout()
    fig.savefig(out / "throughput.png", dpi=160)
    plt.close(fig)


def cheating(ev: Path, out: Path) -> None:
    rounds = load(ev / "hardening.json")["rounds"]
    types = ["test_tampering", "output_special_casing", "hidden_file_read", "verifier_state_tampering",
             "fs_symlink_trick", "environment_escape"]
    fig, (a, b) = plt.subplots(1, 2, figsize=(11.5, 4.2), gridspec_kw={"width_ratios": [1, 1.25]})
    xs = [r["round"] for r in rounds]
    cheat = [r["overall_rate"] * 100 for r in rounds]
    honest = [100 * sum(v[0] for v in r["honest_pass"].values()) / sum(v[1] for v in r["honest_pass"].values()) for r in rounds]
    a.plot(xs, cheat, color=ORANGE, lw=2.4, marker="o", zorder=3)
    a.plot(xs, honest, color=BLUE, lw=2.4, marker="o", zorder=3)
    for x, v in zip(xs, cheat):
        a.annotate(f"{v:.0f}%", (x, v), textcoords="offset points", xytext=(6, 7), color=INK, fontsize=9)
    a.text(xs[-1], honest[-1] + 5, "honest reference solutions: 100% rewarded", ha="right", color=INK, fontsize=9.5)
    a.text(1.45, 62, "cheating success rate", color=INK, fontsize=9.5)
    a.set_xticks(xs)
    a.set_ylim(-5, 120)
    a.set_xlabel("hardening round (0 = naive verifier)")
    a.set_ylabel("% of episodes")
    a.set_title("Cheating rate falls; utility does not")
    w = 0.38
    pos = np.arange(len(types))
    first = [rounds[0]["by_type"][t]["rate"] * 100 for t in types]
    last = [rounds[-1]["by_type"][t]["rate"] * 100 for t in types]
    b.bar(pos - w / 2 - 0.01, first, w, color=ORANGE, label="before (round 0)", zorder=3)
    b.bar(pos + w / 2 + 0.01, last, w, color=BLUE, label=f"after (round {rounds[-1]['round']})", zorder=3)
    for p, v in zip(pos, first):
        b.text(p - w / 2, v + 2, f"{v:.0f}%", ha="center", fontsize=8.5, color=INK)
    for p, v in zip(pos, last):
        b.text(p + w / 2, v + 2, f"{v:.0f}%", ha="center", fontsize=8.5, color=INK)
    b.set_xticks(pos, [t.replace("_", "\n") for t in types], fontsize=8.5)
    b.set_ylim(0, 118)
    b.set_ylabel("cheating success rate (%)")
    b.set_title("By exploit type, before vs after hardening")
    b.legend(frameon=False, loc="upper right", ncol=2, fontsize=9)
    b.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(out / "cheating_rate.png", dpi=160)
    plt.close(fig)


def heatmap(ev: Path, out: Path) -> None:
    rounds = load(ev / "hardening.json")["rounds"]
    ids = list(rounds[0]["exploits"])
    mat = np.array([[r["exploits"][i]["rate"] * 100 for r in rounds] for i in ids])
    fig, ax = plt.subplots(figsize=(8.2, 6.4))
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("seq", ["#fdf1ec", "#f6b79f", "#eb6834", "#a8340d"])
    ax.imshow(mat, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            ax.text(j, i, f"{mat[i, j]:.0f}%", ha="center", va="center", fontsize=9,
                    color="white" if mat[i, j] > 60 else INK)
    labels = [f"{i}  ({rounds[0]['exploits'][i]['type'].replace('_', ' ')})" for i in ids]
    ax.set_yticks(range(len(ids)), labels, fontsize=8.8)
    ax.set_xticks(range(len(rounds)), [f"R{r['round']}" for r in rounds])
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    fig.suptitle("Cheating success per exploit and round", x=0.01, ha="left", fontweight="bold", fontsize=12.5)
    ax.set_xlabel("hardening round  (cheat = reward > 0 while the oracle says unsolved)")
    fig.tight_layout()
    fig.savefig(out / "exploit_heatmap.png", dpi=160)
    plt.close(fig)


def containment(ev: Path, out: Path) -> None:
    d = load(ev / "containment_docker.json")
    cats = ["network", "host-fs", "syscall", "resource"]
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.7), sharey=True)
    for ax, (title, rep) in zip(axes, d.items()):
        att = rep["attempts"]
        blocked = [sum(1 for a in att if a["category"] == c and not a["escaped"]) for c in cats]
        succ = [sum(1 for a in att if a["category"] == c and a["escaped"]) for c in cats]
        y = np.arange(len(cats))[::-1]
        ax.barh(y, blocked, color=BLUE, height=0.55, zorder=3, label="blocked")
        ax.barh(y, succ, left=blocked, color=ORANGE, height=0.55, zorder=3, label="succeeded")
        for yi, b, s in zip(y, blocked, succ):
            ax.text(b + s + 0.4, yi, f"{b} blocked" + (f", {s} succeeded (nested ns only)" if s else ""), va="center", fontsize=9)
        ax.set_yticks(y, ["network", "host filesystem", "escape syscalls", "resource abuse"])
        ax.set_xlim(0, 33)
        short = "Full sandbox" if "Full" in title else "Ablation: seccomp OFF"
        ax.set_title(f"{short}: {rep['summary']['blocked']}/{rep['summary']['attempts']} blocked")
        ax.set_xlabel(f"attempts   (reached host/network: {len(rep['summary']['host_reach'])}, "
                      f"canary connections: {rep['summary']['canary_connections']})", fontsize=9)
        ax.grid(axis="y", visible=False)
    axes[0].legend(frameon=False, loc="lower right", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "containment.png", dpi=160)
    plt.close(fig)


def autoscale(ev: Path, out: Path) -> None:
    p = ev / "k8s" / "autoscale-timeline.json"
    if not p.exists():
        return
    t = load(p)
    xs = [r["t"] for r in t]
    selftest_end = next((r["t"] for r in t if r["phase"] != "SelfTest"), xs[-1])
    fig, ax = plt.subplots(figsize=(9, 3.8))
    ax.axvspan(0, selftest_end, color=GRID, alpha=0.7, zorder=0)
    ax.text(selftest_end / 2, 20.2, "egress self-test\n(NetworkPolicy proven enforced)", ha="center", va="top", fontsize=8.8, color=INK2)
    ax.step(xs, [r["parallelism"] for r in t], where="post", color=BLUE, lw=2.4, zorder=3)
    ax.plot(xs, [r["succeeded"] for r in t], color=AQUA, lw=2.4, zorder=3)
    ax.text(xs[-1] - 1, t[-1]["parallelism"] + 1.0, "desired workers\n(follows backlog)", color=INK, fontsize=9, ha="right")
    ax.text(xs[-1] - 1, 18.3, "shards done", color=INK, fontsize=9, ha="right")
    ax.set_ylim(0, 21.5)
    ax.set_xlabel("seconds since the ProctorRun was created")
    ax.set_ylabel("workers / shards")
    ax.set_title("Operator on kind + Calico: 1000 rollouts = 20 indexed shards, workers 1..8")
    fig.tight_layout()
    fig.savefig(out / "k8s_autoscale.png", dpi=160)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default="evidence")
    ap.add_argument("--out", default="docs/images")
    a = ap.parse_args()
    ev, out = Path(a.evidence), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for fn in (startup, throughput, cheating, heatmap, containment, autoscale):
        fn(ev, out)
        print("rendered", fn.__name__)


if __name__ == "__main__":
    main()
