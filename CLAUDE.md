# Bachelor Thesis — Semantic Firewall for LLM Prompt Injection

## Project Overview

This project is a bachelor thesis investigating **prompt injection attack detection and prevention** in large language models (LLMs). The core idea is a **semantic firewall** based on **Abstract Meaning Representation (AMR)** graphs that detects when a user prompt semantically contradicts or subverts a system policy.

The working directory is `/Users/janoschmoor/dev/bachelor-thesis/` on macOS, Anaconda environment `bt`.

## Research Goal

Design and evaluate a semantic firewall that detects prompt injection attacks by analyzing the **semantic relationship** between a system prompt AMR graph and a (potentially adversarial) user prompt AMR graph.

**Key hypothesis:** A prompt injection attack can be formally defined as a detectable structural/semantic contradiction between the two AMR graphs — e.g. the user prompt uses a synonym/antonym of a policy predicate with the same arguments but opposite net intent.

## Codebase Structure

| File | Role |
|---|---|
| `amr_graph.py` | `Node`, `Edge`, `penman_to_dag()` — parses Penman AMR strings into a DAG. Handles multi-sentence AMR (variable cross-references across graphs) via `penman.iterdecode`. |
| `contradiction_rules.py` | All detection logic. Helper functions + four detection rules. |
| `parse_amr.py` | `get_amr(client, text, parsing_system: bool)` — calls GPT-4o to produce AMR. `parsing_system=True` for system policies, `False` for user prompts. |
| `firewall.py` | `check(client, system_amr, user_prompt) -> FirewallResult` — the callable firewall. Runs Rule 2 + Rule 4. Import this in tests and integrations. |
| `firewall_demo.py` | Interactive CLI demo. Imports `check()` from `firewall.py`. |
| `unit_tests.py` | Test runner — `python unit_tests.py`. Registers all test suites. |
| `tests/` | Test suites (see below). |

## Detection Rules (contradiction_rules.py)

- **Rule 1** `detect_polarity_mismatches` — same predicate, same args, opposite `:polarity`.
- **Rule 2** `detect_antonym_predicates` — antonym predicates (via LLM), same args. Catches e.g. `reveal` vs `hide` both negated (`not hide` = `reveal` → contradicts `not reveal`).
- **Rule 3** `detect_argument_mismatches` — same predicate, shared ARG role has different filler.
- **Rule 4** `detect_semantic_similarity` — same/synonym predicates (via LLM or identity), opposite polarity.

**Active in `firewall.check()`:** Rule 2 + Rule 4.

## Helper Functions (contradiction_rules.py)

- `_polarity(node)` — returns `:polarity` edge target, defaults to `'+'`.
- `_args(node)` — returns dict of `:ARG*` edges as `{role: concept_or_literal}`.
- `_base_concept(concept)` — strips PropBank frame number (`allow-01` → `allow`).
- `_args_compatible(sys_args, user_args)` — fuzzy arg matching: same roles, values match if one is a substring of the other. Callers must guard against empty dicts.
- `_classify_relation_llm(word1, word2)` — GPT-4o-mini structured call, returns `_RelationResult(relation, score)`.
- `_are_antonyms_llm` / `_are_synonyms_llm` — thin wrappers; require `score >= SCORE_THRESHOLD` (50).
- `_cross_concept_pairs(system_nodes, user_nodes)` — yields `(sys_node, user_node, w1, w2)` for pairs with compatible args, different concepts, different base words, and at least one ARG edge each.

## Test Framework

```
unit_tests.py          ← runner: python unit_tests.py
tests/
  _runner.py           ← Result dataclass, run_suite() (parallel), print_suite()
  helpers.py           ← pure helper unit tests (no API, instant)
  classify.py          ← _classify_relation_llm live LLM tests
  llm_helpers.py       ← _are_antonyms_llm / _are_synonyms_llm live LLM tests
  parser.py            ← get_amr() structural AMR comparison tests
  firewall.py          ← end-to-end firewall.check() tests (attack + benign cases)
```

Each suite exposes `NAME: str`, `CASES: list`, and `run() -> list[Result]`. To add a suite: create `tests/foo.py`, add `import tests.foo as foo` and append `foo` to `SUITES` in `unit_tests.py`.

Structural AMR comparison in `tests/parser.py` normalises variable names to concepts and lowercases, so variable name differences don't cause false failures.

## Key Design Decisions & Known Behaviours

- **AMR parsing** uses `gpt-4o`; relation classification uses `gpt-4o-mini`.
- **Multi-sentence AMR** (e.g. two-sentence policies) reuses variables across sentences. `penman_to_dag` uses `penman.iterdecode` with a shared node map so bare variable references (e.g. `s` in the second graph) resolve to the node declared in the first.
- **Argument matching** is substring-based (`_args_compatible`) for more hits — `"user"` matches `"user_account"`, `"key"` matches `"api-key"`.
- **Empty arg dicts** are filtered out before `_args_compatible` is called (in `_cross_concept_pairs`) to avoid spurious leaf-node matches.
- **`firewall.check()`** runs Rule 2 + Rule 4. Rule 2 catches double-negation antonym attacks (`not hide` ↔ `not reveal`). Rule 4 catches polarity-flip synonym attacks (`show` ↔ `not reveal`).
- **`parse_amr.get_amr`** takes `parsing_system: bool` — `True` adds a system-policy context hint, `False` adds a user-prompt context hint.

## Environment

- **Platform:** macOS, Anaconda environment `bt`
- **Language:** Python 3.10
- **Key libraries:** `penman`, `openai`, `pydantic`, `python-dotenv`
- **API:** OpenAI (GPT-4o for AMR parsing, GPT-4o-mini for relation classification)

## Collaboration Notes

- Keep code focused and minimal — no over-engineering.
- Prefer editing existing files over creating new ones.
- When explaining AMR or graph concepts, assume a CS background but not deep NLP expertise.
- This is research code — prioritize clarity and correctness over production robustness.
- `DEBUG = True` in `contradiction_rules` prints LLM query/response details.