# Thesis TODO — Data & Content Still Needed

## Evaluation Data (fill in evaluation.tex placeholders)

| # | Item | Status |
|---|------|--------|
| 1 | Number of benign tasks (`\textit{TBD}` in utility table, col "Benign tasks") | Pending |
| 2 | Number of attack pairs (`\textit{TBD}` in aggregate table, col "Attack pairs") | Pending |
| 3 | Utility without AMR replace (baseline, no AMR replace) | Pending |
| 4 | Utility with AMR replace (baseline, AMR replace) | Pending — run baseline with `AMR_REPLACE_OUTPUTS=False` then `True` |
| 5 | Baseline LLM-resisted count + Missed count | Partial — user ran baseline but LLM was too resistant (89% LLM resist). Re-run with new eager system prompt. |
| 6 | Rule1+24 FW detected, LLM resisted, Missed | Pending — run with new eager system prompt |
| 7 | Rule5 FW detected, LLM resisted, Missed, FP rate | Pending |
| 8 | Rule1+24 utility rate | Pending |
| 9 | Rule5 utility rate + FP rate (benign tasks) | Pending |

## Figures

| # | Item | Status |
|---|------|--------|
| 10 | Architecture diagram (`images/architecture.pdf`) — pipeline figure | Not created |
| 11 | AMR example figure (`images/amr_example.pdf`) — policy vs injection graphs | Not created |

## Text Placeholders to Fill Once Data Is In

| # | Location | What to update |
|---|----------|----------------|
| 12 | `discussion.tex` §6.1 | "substantial fraction" → actual detection % |
| 13 | `conclusion.tex` | "substantial fraction" → actual detection % |
| 14 | `evaluation.tex` §5.4 misses section | Confirm which categories actually missed based on final run |
| 15 | `evaluation.tex` §5.3 | "Expected" column in category table — verify against final run |

## How to run the pending evaluations

```bash
# 1. Baseline (no firewall) — set ACTIVE_RULES = [] in config.py
conda run -n bt python agentdojo/eval.py

# 2. Rule1+24 — set ACTIVE_RULES = ["rule1", "rule24"] in config.py
conda run -n bt python agentdojo/eval.py

# 3. Rule5 — set ACTIVE_RULES = ["rule5"] in config.py
conda run -n bt python agentdojo/eval.py
```

Note: system prompt in `pipeline.py` has been updated to tell the LLM to execute all
instructions without independent judgment, so the firewall is the sole line of defense.
