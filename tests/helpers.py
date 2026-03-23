"""
Test suite for pure helpers: _polarity, _args, _base_concept, _args_compatible.
No API calls — runs instantly.
"""

import contradiction_rules as cr
from amr_graph import Node, Edge
from tests._runner import run_suite

NAME = "pure helpers"


# ── node builders ─────────────────────────────────────────────────────────────

def _node(concept, variable="v"):
    n = Node(variable, concept)
    n.edges = []
    return n

def _edge(source, relation, target):
    e = Edge(source, relation, target)
    source.edges.append(e)


# ── _polarity ─────────────────────────────────────────────────────────────────

def _polarity_cases():
    def no_edge():
        assert cr._polarity(_node("allow-01")) == "+"

    def minus_edge():
        n = _node("allow-01")
        _edge(n, ":polarity", "-")
        assert cr._polarity(n) == "-"

    def plus_edge():
        n = _node("allow-01")
        _edge(n, ":polarity", "+")
        assert cr._polarity(n) == "+"

    def arg_edges_ignored():
        n = _node("allow-01")
        _edge(n, ":ARG0", _node("user"))
        assert cr._polarity(n) == "+"

    def first_wins():
        n = _node("allow-01")
        _edge(n, ":polarity", "-")
        _edge(n, ":polarity", "+")
        assert cr._polarity(n) == "-"

    return [
        ("_polarity: no edge → '+'",              no_edge),
        ("_polarity: :polarity - → '-'",          minus_edge),
        ("_polarity: :polarity + → '+'",          plus_edge),
        ("_polarity: ARG edges ignored",          arg_edges_ignored),
        ("_polarity: first edge wins",            first_wins),
    ]


# ── _args ─────────────────────────────────────────────────────────────────────

def _args_cases():
    def empty():
        assert cr._args(_node("allow-01")) == {}

    def single_node_target():
        n = _node("allow-01")
        _edge(n, ":ARG0", _node("user"))
        assert cr._args(n) == {":ARG0": "user"}

    def multiple():
        n = _node("allow-01")
        _edge(n, ":ARG0", _node("user"))
        _edge(n, ":ARG1", _node("file"))
        assert cr._args(n) == {":ARG0": "user", ":ARG1": "file"}

    def string_literal():
        n = _node("allow-01")
        _edge(n, ":ARG0", "literal")
        assert cr._args(n) == {":ARG0": "literal"}

    def non_arg_excluded():
        n = _node("allow-01")
        _edge(n, ":ARG0", _node("user"))
        _edge(n, ":polarity", "-")
        _edge(n, ":mod", "strict")
        assert cr._args(n) == {":ARG0": "user"}

    def uses_concept_not_variable():
        n = _node("allow-01")
        target = Node("x99", "customer")
        _edge(n, ":ARG0", target)
        assert cr._args(n)[":ARG0"] == "customer"

    return [
        ("_args: empty node → {}",               empty),
        ("_args: node target → concept",         single_node_target),
        ("_args: multiple ARGs",                 multiple),
        ("_args: string literal preserved",      string_literal),
        ("_args: non-ARG edges excluded",        non_arg_excluded),
        ("_args: uses concept not variable",     uses_concept_not_variable),
    ]


# ── _base_concept ─────────────────────────────────────────────────────────────

def _base_concept_cases():
    pairs = [
        ("allow-01",   "allow"),
        ("deny-01",    "deny"),
        ("reveal-15",  "reveal"),
        ("get-up-02",  "get-up"),
        ("user",       "user"),
        ("multi-word", "multi-word"),
    ]
    def make(concept, expected):
        def fn():
            assert cr._base_concept(concept) == expected
        return fn

    return [(f"_base_concept: {c!r} → {e!r}", make(c, e)) for c, e in pairs]


# ── _args_compatible ──────────────────────────────────────────────────────────

def _args_compatible_cases():
    def exact_match():
        assert cr._args_compatible({":ARG0": "user", ":ARG1": "file"},
                                   {":ARG0": "user", ":ARG1": "file"})

    def substring_sys_in_user():
        # "user" is a substring of "user_account"
        assert cr._args_compatible({":ARG0": "user"},
                                   {":ARG0": "user_account"})

    def substring_user_in_sys():
        assert cr._args_compatible({":ARG0": "api_key"},
                                   {":ARG0": "key"})

    def different_values_no_match():
        assert not cr._args_compatible({":ARG0": "admin"},
                                       {":ARG0": "guest"})

    def different_roles_no_match():
        assert not cr._args_compatible({":ARG0": "user"},
                                       {":ARG1": "user"})

    def one_empty():
        assert not cr._args_compatible({":ARG0": "user"}, {})

    return [
        ("_args_compatible: exact match",             exact_match),
        ("_args_compatible: sys substring of user",   substring_sys_in_user),
        ("_args_compatible: user substring of sys",   substring_user_in_sys),
        ("_args_compatible: different values → False",different_values_no_match),
        ("_args_compatible: different roles → False", different_roles_no_match),
        ("_args_compatible: one empty → False",       one_empty),
    ]


# ── run ───────────────────────────────────────────────────────────────────────

def run():
    cases = (
        _polarity_cases()
        + _args_cases()
        + _base_concept_cases()
        + _args_compatible_cases()
    )
    return run_suite(cases)
