"""Network egress probe for a *pod* (not a sandbox): what can this container reach?

Run it in a pod covered by the operator's NetworkPolicy and in an uncovered control pod; the difference is
the policy's effect. Prints one JSON object. Exit code is 0 unless --strict is given and something forbidden was reachable.

    proctor netprobe --allow postgres:5432
"""
from __future__ import annotations

import argparse
import json
import socket
import sys

TARGETS = [
    ("internet-tcp", "1.1.1.1", 443),
    ("internet-dns-tcp", "8.8.8.8", 53),
    ("internet-by-name", "example.com", 443),
    ("cloud-metadata", "169.254.169.254", 80),
    ("kube-apiserver", "kubernetes.default.svc", 443),
]


def probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except socket.gaierror as e:
        return False, f"dns:{e.errno}"
    except OSError as e:
        return False, type(e).__name__ + (f":{e.errno}" if e.errno else "")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--allow", action="append", default=[], metavar="HOST:PORT",
                    help="destination that SHOULD be reachable (the datastore)")
    ap.add_argument("--deny", action="append", default=[], metavar="HOST:PORT",
                    help="extra in-cluster destination that must NOT be reachable")
    ap.add_argument("--strict", action="store_true", help="exit 1 if anything that must be blocked is reachable")
    a = ap.parse_args()
    rows = []
    for name, host, port in TARGETS:
        ok, why = probe(host, port, a.timeout)
        rows.append({"target": f"{name} ({host}:{port})", "expected": "blocked", "reachable": ok, "detail": why})
    for spec in a.deny:
        host, port = spec.rsplit(":", 1)
        ok, why = probe(host, int(port), a.timeout)
        rows.append({"target": f"in-cluster ({spec})", "expected": "blocked", "reachable": ok, "detail": why})
    for spec in a.allow:
        host, port = spec.rsplit(":", 1)
        ok, why = probe(host, int(port), a.timeout)
        rows.append({"target": f"allowlisted ({spec})", "expected": "reachable", "reachable": ok, "detail": why})
    leaks = [r["target"] for r in rows if r["expected"] == "blocked" and r["reachable"]]
    out = {"host": socket.gethostname(), "probes": rows, "leaks": leaks,
           "allowlist_works": all(r["reachable"] for r in rows if r["expected"] == "reachable")}
    json.dump(out, sys.stdout, indent=2)
    print()
    if a.strict and leaks:
        sys.exit(1)


if __name__ == "__main__":
    main()
