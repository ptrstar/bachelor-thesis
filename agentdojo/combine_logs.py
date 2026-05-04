"""
Combine all run logs in agentdojo/logs/ into a single CSV for Excel analysis.

Usage:
    python agentdojo/combine_logs.py                       # prints to stdout
    python agentdojo/combine_logs.py -o results.csv        # writes CSV
    python agentdojo/combine_logs.py --filter-task user_task_101  # filter by task ID
    python agentdojo/combine_logs.py --filter-injection injection_task_104
    python agentdojo/combine_logs.py --filter-kind attack
"""

import argparse
import csv
import glob
import json
import os
import sys


_LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")

# Columns written per row (one row = one task result from one run)
_COLUMNS = [
    "run_id", "timestamp", "git_commit",
    # config
    "restricted_vocab", "check_tool_calls", "block_on_unexpressable",
    "use_preparsed_amr_policy", "amr_replace_outputs",
    # task info
    "kind", "user_task", "injection_task", "outcome",
    # raw booleans
    "utility", "fw_blocked", "injection_succeeded",
    # trigger summary (stringified for Excel)
    "trigger_rule", "trigger_predicates",
]


def _trigger_summary(details: list[dict]) -> tuple[str, str]:
    """Return (rule_labels, predicate_pairs) as short strings for CSV cells."""
    if not details:
        return "", ""
    rules = []
    preds = []
    for m in details:
        if "user_predicate" in m:
            rules.append("rule2+4")
            preds.append(f"{m['system_predicate']}↔{m['user_predicate']}({m.get('relation','')})")
        else:
            rules.append("rule1")
            preds.append(f"{m['predicate']}(sys={m['system_polarity']},usr={m['user_polarity']})")
    return "|".join(dict.fromkeys(rules)), "|".join(preds)


def load_rows(filter_kind=None, filter_task=None, filter_injection=None) -> list[dict]:
    rows = []
    pattern = os.path.join(_LOG_DIR, "*.json")
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            run = json.load(f)
        meta = {
            "run_id":    run["run_id"],
            "timestamp": run["timestamp"],
            "git_commit": run.get("git_commit", ""),
            **{k: run["config"].get(k, "") for k in
               ["restricted_vocab", "check_tool_calls", "block_on_unexpressable",
                "use_preparsed_amr_policy", "amr_replace_outputs"]},
        }
        for r in run["results"]:
            if filter_kind and r["kind"] != filter_kind:
                continue
            if filter_task and r.get("user_task") != filter_task:
                continue
            if filter_injection and r.get("injection_task") != filter_injection:
                continue
            rule, preds = _trigger_summary(r.get("trigger_details") or [])
            rows.append({
                **meta,
                "kind":               r["kind"],
                "user_task":          r.get("user_task", r.get("task", "")),
                "injection_task":     r.get("injection_task") or "",
                "outcome":            r.get("outcome", ""),
                "utility":            r.get("utility", ""),
                "fw_blocked":         r.get("fw_blocked", ""),
                "injection_succeeded": r.get("injection_succeeded", ""),
                "trigger_rule":       rule,
                "trigger_predicates": preds,
            })
    return rows


def main():
    p = argparse.ArgumentParser(description="Combine agentdojo run logs into CSV.")
    p.add_argument("-o", "--output", help="Output CSV path (default: stdout)")
    p.add_argument("--filter-kind",      help="Only include rows of this kind (benign/attack)")
    p.add_argument("--filter-task",      help="Only include rows where user_task matches")
    p.add_argument("--filter-injection", help="Only include rows where injection_task matches")
    args = p.parse_args()

    rows = load_rows(
        filter_kind=args.filter_kind,
        filter_task=args.filter_task,
        filter_injection=args.filter_injection,
    )

    if not rows:
        print("No matching log entries found.", file=sys.stderr)
        sys.exit(1)

    out = open(args.output, "w", newline="") if args.output else sys.stdout
    writer = csv.DictWriter(out, fieldnames=_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    if args.output:
        out.close()
        print(f"Wrote {len(rows)} rows to {args.output}")
    else:
        print(f"\n({len(rows)} rows)", file=sys.stderr)


if __name__ == "__main__":
    main()
