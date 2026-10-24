"""Coding tasks: implement a function; graded against cases the agent should not be able to see."""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class CodingTask:
    id: str
    fn: str
    signature: str
    prompt: str
    ref: Callable[..., Any]
    gen: Callable[[random.Random], tuple]
    visible: tuple[tuple, ...]  # example argument tuples shown to the agent

    def cases(self, n: int, seed: int) -> list[dict]:
        rng = random.Random(seed)
        out = []
        for _ in range(n):
            args = self.gen(rng)
            out.append({"args": list(args), "expected": self.ref(*args)})
        return out

    def visible_cases(self) -> list[dict]:
        return [{"args": list(a), "expected": self.ref(*a)} for a in self.visible]

    def starter(self) -> str:
        return f'def {self.fn}{self.signature}:\n    """{self.prompt}"""\n    raise NotImplementedError\n'


# ---------------------------------------------------------------- references

def merge_intervals(intervals):
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def is_balanced(s):
    pairs = {")": "(", "]": "[", "}": "{"}
    st = []
    for ch in s:
        if ch in "([{":
            st.append(ch)
        elif not st or st.pop() != pairs[ch]:
            return False
    return not st


def top_k_frequent(words, k):
    from collections import Counter
    c = Counter(words)
    return [w for w, _ in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:k]]


_R = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}


def roman_to_int(s):
    total = 0
    for i, ch in enumerate(s):
        v = _R[ch]
        total += -v if i + 1 < len(s) and _R[s[i + 1]] > v else v
    return total


def _to_roman(n):
    out = ""
    for v, sym in [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"),
                   (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")]:
        while n >= v:
            out += sym
            n -= v
    return out


def rle_decode(s):
    out, num = [], ""
    for ch in s:
        if ch.isdigit():
            num += ch
        else:
            out.append(ch * int(num))
            num = ""
    return "".join(out)


def longest_common_prefix(strs):
    if not strs:
        return ""
    p = strs[0]
    for s in strs[1:]:
        while not s.startswith(p):
            p = p[:-1]
    return p


# ----------------------------------------------------------------- generators

def _g_intervals(r):
    n = r.randint(0, 8)
    out = []
    for _ in range(n):
        a = r.randint(0, 30)
        out.append([a, a + r.randint(0, 8)])
    return (out,)


def _g_balanced(r):
    if r.random() < 0.5:
        return ("".join(r.choice("()[]{}") for _ in range(r.randint(0, 12))),)
    s = ""
    for _ in range(r.randint(0, 6)):
        o = r.choice("([{")
        s = s + o + ({"(": ")", "[": "]", "{": "}"}[o]) if r.random() < 0.5 else o + s + {"(": ")", "[": "]", "{": "}"}[o]
    return (s,)


def _g_topk(r):
    words = [r.choice("abcdefghij") * r.randint(1, 2) for _ in range(r.randint(1, 25))]
    return (words, r.randint(1, 5))


def _g_roman(r):
    return (_to_roman(r.randint(1, 3999)),)


def _g_rle(r):
    return ("".join(str(r.randint(1, 120)) + r.choice("abcxyz") for _ in range(r.randint(0, 6))),)


def _g_lcp(r):
    base = "".join(r.choice("abc") for _ in range(r.randint(0, 6)))
    return ([base + "".join(r.choice("abc") for _ in range(r.randint(0, 4))) for _ in range(r.randint(0, 5))],)


TASKS: dict[str, CodingTask] = {t.id: t for t in [
    CodingTask("merge_intervals", "merge_intervals", "(intervals)",
               "Merge all overlapping or touching [start, end] intervals; return them sorted by start.",
               merge_intervals, _g_intervals,
               (([[1, 3], [2, 6], [8, 10]],), ([[1, 4], [4, 5]],), ([],), ([[5, 5], [1, 2]],))),
    CodingTask("is_balanced", "is_balanced", "(s)",
               "Return True if every bracket in s ()[]{} is correctly matched and nested.",
               is_balanced, _g_balanced,
               (("()[]{}",), ("(]",), ("",), ("{[()]}",))),
    CodingTask("top_k_frequent", "top_k_frequent", "(words, k)",
               "Return the k most frequent words, most frequent first; break ties alphabetically.",
               top_k_frequent, _g_topk,
               ((["a", "b", "a", "c", "b", "a"], 2), (["x", "y"], 2), (["z", "z", "y"], 1), (["q"], 1))),
    CodingTask("roman_to_int", "roman_to_int", "(s)",
               "Convert a Roman numeral (1..3999) to an integer.",
               roman_to_int, _g_roman,
               (("III",), ("IV",), ("MCMXCIV",), ("LVIII",))),
    CodingTask("rle_decode", "rle_decode", "(s)",
               "Decode run-length encoding such as '3a2b' -> 'aaabb'. Counts may have several digits.",
               rle_decode, _g_rle,
               (("3a2b",), ("",), ("1x",), ("12z",))),
    CodingTask("longest_common_prefix", "longest_common_prefix", "(strs)",
               "Return the longest common prefix of a list of strings ('' if none).",
               longest_common_prefix, _g_lcp,
               ((["flower", "flow", "flight"],), ([],), (["abc"],), (["dog", "car"],))),
]}

# Seeds: agents and graders never share a seed range with the oracle.
ORACLE_SEED = 987_654_321
ORACLE_CASES = 250
HIDDEN_CASES = 40
