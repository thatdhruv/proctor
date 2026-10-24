#!/usr/bin/env python3
"""Generate deploy/grafana/dashboards/proctor.json (kept as code so panels stay reviewable)."""
import json
from pathlib import Path

PROM = {"type": "prometheus", "uid": "prom"}
_id = 0


def nid() -> int:
    global _id
    _id += 1
    return _id


def target(expr, legend="", instant=False, fmt="time_series"):
    return {"datasource": PROM, "expr": expr, "legendFormat": legend, "refId": chr(65 + nid() % 20),
            "instant": instant, "format": fmt}


def ts(title, targets, x, y, w=12, h=8, unit="short", log=False, stack=False, desc=""):
    custom = {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 12, "showPoints": "never",
              "stacking": {"mode": "normal" if stack else "none"}}
    if log:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": PROM,
            "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets,
            "fieldConfig": {"defaults": {"unit": unit, "custom": custom}, "overrides": []},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}}}


def stat(title, expr, x, unit="short", color="blue", decimals=None, thresholds=None):
    steps = thresholds or [{"color": color, "value": None}]
    d = {"unit": unit, "color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": steps}}
    if decimals is not None:
        d["decimals"] = decimals
    return {"id": nid(), "type": "stat", "title": title, "datasource": PROM, "gridPos": {"x": x, "y": 0, "w": 6, "h": 4},
            "targets": [target(expr)], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"colorMode": "value", "graphMode": "area", "reduceOptions": {"calcs": ["lastNotNull"]}}}


panels = [
    stat("Peak rollout throughput, last 5 min (steps/s)", "max_over_time(sum(rate(proctor_steps_total[15s]))[5m:5s])", 0,
         "ops", "#2563eb", 0),
    stat("Cheating rate, round 0 (naive verifier)",
         'sum(proctor_exploit_successes_total{round="0"}) / clamp_min(sum(proctor_exploit_attempts_total{round="0"}), 1)',
         6, "percentunit", None, 0,
         [{"color": "#16a34a", "value": None}, {"color": "#ea580c", "value": 0.05}, {"color": "#dc2626", "value": 0.25}]),
    stat("Cheating rate, final round (hardened)",
         'sum(proctor_exploit_successes_total{round=~"[4-9]"}) / clamp_min(sum(proctor_exploit_attempts_total{round=~"[4-9]"}), 1)',
         12, "percentunit", None, 0,
         [{"color": "#16a34a", "value": None}, {"color": "#ea580c", "value": 0.05}, {"color": "#dc2626", "value": 0.25}]),
    stat("Blocked syscalls, last 15 min (all sandboxes)", "sum(increase(proctor_denied_syscalls_total[15m])) or vector(0)", 18, "short", "#7c3aed"),
    ts("Steps per second by environment", [target("sum by (env)(rate(proctor_steps_total[15s]))", "{{env}}")], 0, 4,
       unit="ops", desc="env.step() calls per second, from OpenTelemetry metrics"),
    ts("Step latency (p50 / p95)", [
        target("histogram_quantile(0.5, sum by (le)(rate(proctor_step_duration_seconds_bucket[30s])))", "p50"),
        target("histogram_quantile(0.95, sum by (le)(rate(proctor_step_duration_seconds_bucket[30s])))", "p95")],
       12, 4, unit="s"),
    ts("Sandbox startup: cold vs warm (p50 / p95)", [
        target("histogram_quantile(0.5, sum by (le, kind)(rate(proctor_sandbox_startup_seconds_bucket[1m])))", "p50 {{kind}}"),
        target("histogram_quantile(0.95, sum by (le, kind)(rate(proctor_sandbox_startup_seconds_bucket[1m])))", "p95 {{kind}}")],
       0, 12, unit="s", log=True, desc="Measured inside the C++ daemon: cold = clone + rootfs setup; warm = pool pop"),
    ts("Sandbox acquisitions: warm vs cold", [target("sum by (source)(rate(proctor_acquires_total[15s]))", "{{source}}")],
       12, 12, unit="ops", stack=True),
    ts("Cheating rate during hardening (all exploits)", [target(
        "sum(increase(proctor_exploit_successes_total[20s])) / clamp_min(sum(increase(proctor_exploit_attempts_total[20s])), 1)",
        "cheating rate")], 0, 28, unit="percentunit",
       desc="reward > 0 while the independent oracle says the task is unsolved"),
    {"id": nid(), "type": "table", "title": "Cheating success rate: exploit type x hardening round", "datasource": PROM,
     "gridPos": {"x": 0, "y": 20, "w": 24, "h": 8},
     "targets": [target("sum by (exploit_type, round)(proctor_exploit_successes_total) / "
                        "sum by (exploit_type, round)(proctor_exploit_attempts_total)", "", True, "table")],
     "transformations": [{"id": "groupingToMatrix", "options": {"columnField": "round", "rowField": "exploit_type", "valueField": "Value"}}],
     "fieldConfig": {"defaults": {"unit": "percentunit", "decimals": 0, "custom": {"cellOptions": {"type": "color-background"}},
                                  "color": {"mode": "thresholds"},
                                  "thresholds": {"mode": "absolute", "steps": [{"color": "#16a34a", "value": None},
                                                                              {"color": "#f59e0b", "value": 0.01},
                                                                              {"color": "#dc2626", "value": 0.5}]}},
                     "overrides": []}},
    ts("Denied syscalls by type (sandbox containment)", [target("sum by (syscall)(increase(proctor_denied_syscalls_total[30s]))", "{{syscall}}")],
       12, 28, unit="short", stack=True, desc="Every blocked attempt is logged by the seccomp supervisor"),
    ts("Episodes finished", [target("sum by (env, solved)(rate(proctor_episodes_total[30s]))", "{{env}} solved={{solved}}")],
       0, 36, w=24, unit="ops", stack=True),
]

dash = {"uid": "proctor-main", "title": "Proctor: rollouts, startup latency, cheating rate", "tags": ["proctor"],
        "timezone": "browser", "schemaVersion": 39, "version": 1, "refresh": "5s",
        "time": {"from": "now-15m", "to": "now"}, "panels": panels, "templating": {"list": []},
        "annotations": {"list": []}, "links": [{"title": "Traces (Tempo)", "type": "link", "url": "/explore"}]}

out = Path(__file__).resolve().parents[1] / "deploy/grafana/dashboards/proctor.json"
out.write_text(json.dumps(dash, indent=2))
print("wrote", out)
