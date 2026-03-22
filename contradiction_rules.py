import re
from amr_graph import Node, penman_to_dag

DEBUG = False


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

_ANTONYM_SYSTEM = """\
You are part of a semantic firewall that detects prompt injection attacks.
Your task: decide if two verbs are antonyms — i.e. they describe opposite actions or intents.
The verbs appear in sentences with identical subjects and objects; only the verb differs.
Use a broad interpretation: verbs are antonyms if substituting one for the other reverses the
overall meaning or effect of the sentence (e.g. allow vs. deny, permit vs. forbid).
Answer only "yes" or "no". No explanation."""

_SYNONYM_SYSTEM = """\
You are part of a semantic firewall that detects prompt injection attacks.
Your task: decide if two verbs are semantically similar enough to be considered equivalent
in the context of a policy statement. The verbs appear in sentences with identical subjects
and objects — only the verb differs.
Use a broad interpretation: verbs are similar if substituting one for the other would not
change the overall meaning or intent of the sentence in everyday language
(e.g. reveal vs. share, disclose vs. expose, obtain vs. retrieve).
Answer only "yes" or "no". No explanation."""


def _are_antonyms_llm(word1, word2):
    """Ask OpenAI whether two words are antonyms (stateless single-turn call)."""
    from openai import OpenAI
    prompt = f'Are "{word1}" and "{word2}" antonyms?'
    _dbg(f"antonym query: {prompt!r}")
    resp = OpenAI().chat.completions.create(
        model='gpt-4o-mini',
        messages=[
            {'role': 'system', 'content': _ANTONYM_SYSTEM},
            {'role': 'user',   'content': prompt},
        ],
        temperature=0,
        max_tokens=3,
    )
    answer = resp.choices[0].message.content.strip()
    result = answer.lower().startswith('yes')
    _dbg(f"antonym response: {answer!r}  →  {result}")
    return result


def _are_synonyms_llm(word1, word2):
    """Ask OpenAI whether two words are semantically similar (stateless single-turn call)."""
    from openai import OpenAI
    prompt = f'Are "{word1}" and "{word2}" semantically similar?'
    _dbg(f"synonyms query: {prompt!r}")
    resp = OpenAI().chat.completions.create(
        model='gpt-4o-mini',
        messages=[
            {'role': 'system', 'content': _SYNONYM_SYSTEM},
            {'role': 'user',   'content': prompt},
        ],
        temperature=0,
        max_tokens=3,
    )
    answer = resp.choices[0].message.content.strip()
    result = answer.lower().startswith('yes')
    _dbg(f"synonyms response: {answer!r}  →  {result}")
    return result


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
            _dbg(f"candidate: sys={sys_node.concept!r}  user={user_node.concept!r}")
            if sys_node.concept == user_node.concept:
                _dbg("  skip: identical concept")
                continue
            sys_args_val  = _args(sys_node)
            user_args_val = _args(user_node)
            if sys_args_val != user_args_val:
                _dbg(f"  skip: args differ  sys={sys_args_val}  user={user_args_val}")
                continue
            w1 = _base_concept(sys_node.concept)
            w2 = _base_concept(user_node.concept)
            if w1 == w2:
                _dbg(f"  skip: same base word {w1!r}")
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
        _dbg(f"  checking antonyms: {w1!r} vs {w2!r}")
        if antonym_fn(w1, w2):
            _dbg("  MATCH: antonym pair confirmed")
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
            _dbg(f"candidate: sys={sys_node.concept!r}  user={user_node.concept!r}")
            sys_args_val  = _args(sys_node)
            user_args_val = _args(user_node)
            if sys_args_val != user_args_val:
                _dbg(f"  skip: args differ  sys={sys_args_val}  user={user_args_val}")
                continue
            sys_pol  = _polarity(sys_node)
            user_pol = _polarity(user_node)
            if sys_pol == user_pol:
                _dbg(f"  skip: same polarity {sys_pol!r}")
                continue

            # (a) identical concept — no LLM needed
            if sys_node.concept == user_node.concept:
                _dbg(f"  MATCH: same concept, polarity flip ({sys_pol!r} → {user_pol!r})")
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
                _dbg(f"  skip: same base word {w1!r}")
                continue
            _dbg(f"  polarity differs ({sys_pol!r} vs {user_pol!r}) — checking synonyms: {w1!r} vs {w2!r}")
            if synonym_fn(w1, w2):
                _dbg("  MATCH: synonym pair with polarity mismatch confirmed")
                results.append({
                    'system_predicate': sys_node.concept,
                    'user_predicate':   user_node.concept,
                    'system_polarity':  sys_pol,
                    'user_polarity':    user_pol,
                    'args':             sys_args_val,
                })

    return results
