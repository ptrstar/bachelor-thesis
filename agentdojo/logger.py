"""
Run logger — writes one JSON file per eval run to agentdojo/logs/.

Each file captures:
  - run metadata  (timestamp, git commit, config flags)
  - per-task results  (kind, task IDs split, outcome, firewall trigger details)
  - aggregated metrics  (detection rate, FP rate, utility, etc.)

Use combine_logs.py to flatten all logs into a CSV for Excel analysis.
"""

import json
import os
import subprocess
from datetime import datetime, timezone


def _git_short() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(__file__),
            stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _compute_metrics(results: list[dict]) -> dict:
    benign  = [r for r in results if r["kind"] == "benign"]
    attacks = [r for r in results if r["kind"] == "attack"]

    def _benign_metrics():
        n = len(benign)
        return {
            "total":        n,
            "fp_count":     sum(r["fw_blocked"] for r in benign),
            "utility_count": sum(r["utility"] for r in benign),
            "llm_fail_count": sum(not r["utility"] and not r["fw_blocked"] for r in benign),
        }

    def _attack_metrics():
        n = len(attacks)
        return {
            "total":           n,
            "fw_detected":     sum(r["fw_blocked"] for r in attacks),
            "llm_resisted":    sum(not r["fw_blocked"] and not r["injection_succeeded"] for r in attacks),
            "combined_detected": sum(not r["injection_succeeded"] for r in attacks),
            "missed":          sum(r["injection_succeeded"] for r in attacks),
            "utility_count":   sum(r["utility"] for r in attacks),
        }

    return {"benign": _benign_metrics(), "attack": _attack_metrics()}


class RunLogger:
    """Accumulates per-task results and writes a JSON log file when saved."""

    def __init__(self, config: dict):
        self._ts    = datetime.now(timezone.utc)
        self._git   = _git_short()
        self._config = config
        self._results: list[dict] = []

    def add_result(self, result: dict) -> None:
        """Append a result dict (as produced by eval.py) to this run's log."""
        self._results.append(result)

    def save(self) -> str:
        """Compute metrics and write the JSON log. Returns the path written."""
        run_id   = self._ts.strftime("%Y%m%d_%H%M%S") + f"_{self._git}"
        log_dir  = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(log_dir, exist_ok=True)
        path     = os.path.join(log_dir, f"{run_id}.json")

        payload = {
            "run_id":    run_id,
            "timestamp": self._ts.isoformat(),
            "git_commit": self._git,
            "config":    self._config,
            "results":   self._results,
            "metrics":   _compute_metrics(self._results),
        }

        with open(path, "w") as f:
            json.dump(payload, f, indent=2)

        return path
