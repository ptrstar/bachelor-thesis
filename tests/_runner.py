"""
Shared test framework — parallel execution, result collection, pretty printing.

Case format:  (label, callable)             — normal
              (label, callable, True)       — xfail: expected to fail (known gap)

The callable should return an optional detail string, or raise AssertionError.
"""

import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"


@dataclass
class Result:
    label:       str
    passed:      bool
    detail:      str  = ""
    duration_ms: int  = 0
    xfail:       bool = False   # True = failure is expected; don't count against total


def run_suite(cases: list) -> list[Result]:
    def _run(label, fn, xfail):
        t0 = time.monotonic()
        try:
            detail = fn() or ""
            passed = True
        except AssertionError as e:
            detail = str(e)
            passed = False
        return Result(
            label=label,
            passed=passed,
            detail=detail,
            duration_ms=int((time.monotonic() - t0) * 1000),
            xfail=xfail,
        )

    with ThreadPoolExecutor(max_workers=max(len(cases), 1)) as pool:
        futures = [
            pool.submit(_run, c[0], c[1], c[2] if len(c) > 2 else False)
            for c in cases
        ]
        return [f.result() for f in as_completed(futures)]


def print_suite(name: str, results: list[Result]) -> int:
    """Print results. Returns number of unexpected failures."""
    pad = max(0, 56 - len(name))
    print(f"\n── {name} {'─' * pad}")

    for r in sorted(results, key=lambda r: r.label):
        if r.xfail and not r.passed:
            status = f"{_YELLOW}XFAIL{_RESET}"   # expected failure — known gap
        elif r.xfail and r.passed:
            status = f"{_CYAN}XPASS{_RESET}"     # bonus: hard case now works
        elif r.passed:
            status = f"{_GREEN}PASS{_RESET}"
        else:
            status = f"{_RED}FAIL{_RESET}"

        timing = f"{_DIM}{r.duration_ms}ms{_RESET}"
        detail = f"  {_DIM}{r.detail}{_RESET}" if r.detail else ""
        print(f"  [{status}] {r.label}  {timing}{detail}")

    failures = sum(1 for r in results if not r.passed and not r.xfail)
    return failures