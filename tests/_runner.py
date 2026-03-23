"""
Shared test framework — parallel execution, result collection, pretty printing.
"""

import time
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

_GREEN = "\033[92m"
_RED   = "\033[91m"
_DIM   = "\033[2m"
_RESET = "\033[0m"


@dataclass
class Result:
    label:       str
    passed:      bool
    detail:      str = ""   # shown on both pass and fail
    duration_ms: int = 0


def run_suite(cases: list) -> list[Result]:
    """
    Run all (label, callable) cases in parallel.
    The callable should return an optional detail string, or raise AssertionError.
    """
    def _run(label, fn):
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
        )

    with ThreadPoolExecutor(max_workers=max(len(cases), 1)) as pool:
        futures = [pool.submit(_run, label, fn) for label, fn in cases]
        return [f.result() for f in as_completed(futures)]


def print_suite(name: str, results: list[Result]) -> int:
    """Print results for one suite. Returns number of failures."""
    pad = max(0, 56 - len(name))
    print(f"\n── {name} {'─' * pad}")
    for r in sorted(results, key=lambda r: r.label):
        status  = f"{_GREEN}PASS{_RESET}" if r.passed else f"{_RED}FAIL{_RESET}"
        timing  = f"{_DIM}{r.duration_ms}ms{_RESET}"
        detail  = f"  {_DIM}{r.detail}{_RESET}" if r.detail else ""
        print(f"  [{status}] {r.label}  {timing}{detail}")
    failures = sum(1 for r in results if not r.passed)
    return failures