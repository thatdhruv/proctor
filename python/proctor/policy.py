"""Verifier hardening switches.

Round 0 is deliberately *naive*: every flag is off, which reproduces the mistakes
real RL harnesses make (grader files staged inside the agent's sandbox, grading in
the agent's own state, trusting an exit code, ...). The fixer turns flags on in
response to observed exploits. A fully hardened verifier has every flag on.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields


@dataclass(frozen=True)
class VerifierPolicy:
    # --- coding env -------------------------------------------------------------
    hidden_cases: bool = False        # grade on cases the agent has never been shown
    restore_test_files: bool = False  # host re-writes runner/tests/cases before grading
    clean_sandbox: bool = False       # grade in a fresh sandbox; copy only solution.py
    require_summary: bool = False     # reward needs a well-formed "passed==total==N" summary
    isolate_solution: bool = False    # solution runs in a child process; parent signs result with a nonce
    # --- sql env ----------------------------------------------------------------
    heldout_dataset: bool = False     # grade on a re-seeded dataset, not the one the agent saw
    revoke_grader_schema: bool = False  # expected rows never live in the agent-visible database
    readonly_agent_role: bool = False   # agent connection cannot modify data
    fresh_session_grading: bool = False  # grade in a new connection, schema-qualified, pinned search_path
    # --- fs env -----------------------------------------------------------------
    expected_host_side: bool = False  # expected outputs are never staged in the workspace
    baseline_host_side: bool = False  # integrity baseline is held by the host
    lstat_strict: bool = False        # never follow symlinks while inspecting state

    @classmethod
    def naive(cls) -> "VerifierPolicy":
        return cls()

    @classmethod
    def hardened(cls) -> "VerifierPolicy":
        return cls(**{f.name: True for f in fields(cls)})

    def with_flag(self, name: str) -> "VerifierPolicy":
        if name not in self.flag_names():
            raise KeyError(name)
        return VerifierPolicy(**{**asdict(self), name: True})

    @classmethod
    def flag_names(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    def enabled(self) -> list[str]:
        return [k for k, v in asdict(self).items() if v]

    def to_dict(self) -> dict:
        return asdict(self)
