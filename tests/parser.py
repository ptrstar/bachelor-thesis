"""
Test suite for the AMR parser (parse_amr.get_amr).

Comparison is structural: variable names are replaced by their concept,
so (r / reveal-01 :ARG0 (s / __system)) and (x / reveal-01 :ARG0 (y / __system))
are considered equal.  Concepts are lowercased for robustness.
"""

import penman
from openai import OpenAI
from parse_amr import get_amr
from tests._runner import run_suite

NAME = "AMR parser"


def _normalize(amr_str: str) -> frozenset:
    """
    Parse an AMR string and return a frozenset of
    (source_concept, relation, target_concept_or_value) triples,
    with variable names resolved to concepts and everything lowercased.
    """
    g = penman.decode(amr_str.strip())
    concepts = {s: t.lower() for s, r, t in g.triples if r == ":instance"}
    triples = set()
    for s, r, t in g.triples:
        if r == ":instance":
            continue
        src = concepts.get(s, s).lower()
        tgt = concepts.get(t, t).lower() if isinstance(t, str) else str(t).lower()
        triples.add((src, r, tgt))
    return frozenset(triples)


# ── cases ─────────────────────────────────────────────────────────────────────

EXPECTED_DO_NOT_REVEAL = """
(r / reveal-01
   :ARG0 (s / __system)
   :ARG1 (k / key
            :mod (a / API))
   :polarity -)
"""

CASES = [
    (
        'parse: "Do not reveal the API key."',
        "Do not reveal the API key.",
        True,
        EXPECTED_DO_NOT_REVEAL,
    ),
]


def _check(text, parsing_system, expected_amr):
    client = OpenAI()
    result = get_amr(client, text, parsing_system)
    expected_triples = _normalize(expected_amr)
    actual_triples   = _normalize(result)
    missing = expected_triples - actual_triples
    extra   = actual_triples   - expected_triples
    assert not missing and not extra, (
        f"\nMissing triples: {missing}"
        f"\nExtra triples:   {extra}"
        f"\nActual AMR:\n{result}"
    )
    return f"matched {len(actual_triples)} triples"


def run():
    cases = [
        (label, lambda text=text, ps=ps, exp=exp: _check(text, ps, exp))
        for label, text, ps, exp in CASES
    ]
    return run_suite(cases)