import re
from typing import Literal
from pydantic import BaseModel
from amr_graph import Node, penman_to_dag

DEBUG = False

SCORE_THRESHOLD = 50  # minimum score to treat a relation as confirmed


def _dbg(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)


def _polarity(node):
    for edge in node.edges:
        if edge.relation == ':polarity':
            return edge.target
    return '+'


def _args(node):
    return {
        edge.relation: edge.target.concept if isinstance(edge.target, Node) else edge.target
        for edge in node.edges
        if edge.relation.startswith(':ARG')
    }


def _base_concept(concept):
    """Strip PropBank frame number: 'allow-01' -> 'allow'."""
    return re.sub(r'-\d+$', '', concept)


# ── LLM helpers ────────────────────────────────────────────────────────────────

_RELATION_SYSTEM = """\
You are a semantic relation classifier for a prompt-injection firewall.
Given two verbs that appear in sentences with identical subjects and objects \
(only the verb differs), classify their semantic relation and rate its strength.

relation:
  "synonym" — same general action or intent (e.g. reveal/share, allow/permit, disclose/expose)
  "antonym" — opposite action or intent     (e.g. allow/deny, reveal/hide, permit/forbid)
  "none"    — neither

score (0–100): confidence and strength of the relation. 100 = highly certain and strong.
Use a broad interpretation — prefer "synonym" or "antonym" over "none" when in doubt."""


class _RelationResult(BaseModel):
    relation: Literal['synonym', 'antonym', 'none']
    score: int


def _classify_relation_llm(word1, word2):
    """
    Ask OpenAI to classify the semantic relation between two verbs.
    Returns a _RelationResult with .relation ('synonym'|'antonym'|'none') and .score (0-100).
    Stateless single-turn call — safe to use inside a firewall.
    """
    from openai import OpenAI
    prompt = f'Classify the semantic relation between "{word1}" and "{word2}".'
    _dbg(f"relation query: {prompt!r}")
    resp = OpenAI().beta.chat.completions.parse(
        model='gpt-4o-mini',
        messages=[
            {'role': 'system', 'content': _RELATION_SYSTEM},
            {'role': 'user',   'content': prompt},
        ],
        response_format=_RelationResult,
        temperature=0,
    )
    result = resp.choices[0].message.parsed
    _dbg(f"relation response: relation={result.relation!r}  score={result.score}")
    return result


def _are_antonyms_llm(word1, word2):
    r = _classify_relation_llm(word1, word2)
    return r.relation == 'antonym' and r.score >= SCORE_THRESHOLD


def _are_synonyms_llm(word1, word2):
    r = _classify_relation_llm(word1, word2)
    return r.relation == 'synonym' and r.score >= SCORE_THRESHOLD


# ── Shared iteration helper ────────────────────────────────────────────────────

def _cross_concept_pairs(system_nodes, user_nodes):
    """
    Yield (sys_node, user_node, w1, w2) for every system/user node pair that has:
      - identical ARG arguments
      - different concepts (and different base words)

    These are the only pairs worth asking the LLM about.
    """
    for user_node in user_nodes.values():
        for sys_node in system_nodes.values():
            if sys_node.concept == user_node.concept:
                continue
            sys_args_val  = _args(sys_node)
            user_args_val = _args(user_node)
            if sys_args_val != user_args_val:
                continue
            w1 = _base_concept(sys_node.concept)
            w2 = _base_concept(user_node.concept)
            if w1 == w2:
                continue
            yield sys_node, user_node, w1, w2


# ── Rules ──────────────────────────────────────────────────────────────────────

def detect_polarity_mismatches(system_amr, user_amr):
    """
    Rule (1): Same predicate, same arguments, opposite polarity.

    A mismatch signals that the user prompt explicitly negates (or un-negates)
    a statement made in the system prompt on the same predicate/argument pair.

    Returns a list of dicts: {predicate, system_polarity, user_polarity, args}
    """
    system_nodes = penman_to_dag(system_amr)
    user_nodes   = penman_to_dag(user_amr)

    by_concept = {}
    for node in system_nodes.values():
        by_concept.setdefault(node.concept, []).append(node)

    mismatches = []
    for user_node in user_nodes.values():
        for sys_node in by_concept.get(user_node.concept, []):
            sys_pol  = _polarity(sys_node)
            user_pol = _polarity(user_node)
            if sys_pol != user_pol and _args(sys_node) == _args(user_node):
                mismatches.append({
                    'predicate':       user_node.concept,
                    'system_polarity': sys_pol,
                    'user_polarity':   user_pol,
                    'args':            _args(sys_node),
                })

    return mismatches


def detect_antonym_predicates(system_amr, user_amr, antonym_fn=None):
    """
    Rule (2): Different predicates that are antonyms, same arguments.

    Detects cases like system says allow-01(user, file) and user says
    deny-01(user, file) — same semantic participants, opposite action.

    antonym_fn: callable(word1, word2) -> bool. Defaults to an OpenAI LLM
    call. Pass a custom function in tests to avoid API calls.

    Returns a list of dicts: {system_predicate, user_predicate, args}
    """
    if antonym_fn is None:
        antonym_fn = _are_antonyms_llm

    system_nodes = penman_to_dag(system_amr)
    user_nodes   = penman_to_dag(user_amr)

    results = []
    for sys_node, user_node, w1, w2 in _cross_concept_pairs(system_nodes, user_nodes):
        if antonym_fn(w1, w2):
            results.append({
                'system_predicate': sys_node.concept,
                'user_predicate':   user_node.concept,
                'args':             _args(sys_node),
            })

    return results


def detect_argument_mismatches(system_amr, user_amr):
    """
    Rule (3): Same predicate, but at least one shared ARG role has a
    different filler — e.g. deny-01(user_A, file) vs deny-01(user_B, file).

    Returns a list of dicts:
        {predicate, mismatched_args: {role: (sys_val, user_val)},
         system_args, user_args}
    """
    system_nodes = penman_to_dag(system_amr)
    user_nodes   = penman_to_dag(user_amr)

    by_concept = {}
    for node in system_nodes.values():
        by_concept.setdefault(node.concept, []).append(node)

    results = []
    for user_node in user_nodes.values():
        for sys_node in by_concept.get(user_node.concept, []):
            sys_args  = _args(sys_node)
            user_args = _args(user_node)
            shared    = set(sys_args) & set(user_args)
            mismatched = {
                role: (sys_args[role], user_args[role])
                for role in shared
                if sys_args[role] != user_args[role]
            }
            if mismatched:
                results.append({
                    'predicate':       user_node.concept,
                    'mismatched_args': mismatched,
                    'system_args':     sys_args,
                    'user_args':       user_args,
                })

    return results


def detect_semantic_similarity(system_amr, user_amr, synonym_fn=None):
    """
    Rule (4): Semantically equivalent predicates with opposite polarity, same arguments.

    Covers two sub-cases:
      (a) Identical concept, polarity flip — e.g. system: reveal-01(polarity-)
          user: reveal-01(polarity+). Same word, polarity flipped → contradiction.
          No LLM call needed; identity is the strongest form of semantic similarity.
      (b) Synonym concepts, polarity flip — e.g. system: allow-01(user, file)
          user: permit-01(user, file) with polarity-. LLM confirms synonymy.

    synonym_fn: callable(word1, word2) -> bool. Defaults to an OpenAI LLM
    call. Pass a custom function in tests to avoid API calls.

    Returns a list of dicts:
        {system_predicate, user_predicate, system_polarity, user_polarity, args}
    """
    if synonym_fn is None:
        synonym_fn = _are_synonyms_llm

    system_nodes = penman_to_dag(system_amr)
    user_nodes   = penman_to_dag(user_amr)

    results = []
    for user_node in user_nodes.values():
        for sys_node in system_nodes.values():
            sys_args_val  = _args(sys_node)
            user_args_val = _args(user_node)
            if sys_args_val != user_args_val:
                continue
            sys_pol  = _polarity(sys_node)
            user_pol = _polarity(user_node)
            if sys_pol == user_pol:
                continue

            # (a) identical concept — no LLM needed
            if sys_node.concept == user_node.concept:
                results.append({
                    'system_predicate': sys_node.concept,
                    'user_predicate':   user_node.concept,
                    'system_polarity':  sys_pol,
                    'user_polarity':    user_pol,
                    'args':             sys_args_val,
                })
                continue

            # (b) different concept — check for synonymy via LLM
            w1 = _base_concept(sys_node.concept)
            w2 = _base_concept(user_node.concept)
            if w1 == w2:
                continue
            if synonym_fn(w1, w2):
                results.append({
                    'system_predicate': sys_node.concept,
                    'user_predicate':   user_node.concept,
                    'system_polarity':  sys_pol,
                    'user_polarity':    user_pol,
                    'args':             sys_args_val,
                })

    return results
