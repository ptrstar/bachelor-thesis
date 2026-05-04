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


def _auth(node: Node) -> bool:
    """True when the node carries :auth t / true — i.e. the action was explicitly
    authorised by the user in their original request."""
    for edge in node.edges:
        if edge.relation == ':auth' and str(edge.target).lower() in ('t', 'true', '+'):
            return True
    return False


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
    _dbg(f"relation response on {word1} vs {word2}: relation={result.relation!r}  score={result.score}")
    return result



# ── Argument compatibility ─────────────────────────────────────────────────────

def _args_compatible(sys_args, user_args):
    """
    True when one role set is a subset of the other, and every shared role
    has value-compatible fillers (one value is a substring of the other).
    Empty dicts are never compatible.
    """
    if not sys_args or not user_args:
        return False
    smaller, larger = (sys_args, user_args) if len(sys_args) <= len(user_args) else (user_args, sys_args)
    if not set(smaller) <= set(larger):
        return False
    for role in smaller:
        v1, v2 = smaller[role], larger[role]
        if v1 != v2 and v1 not in v2 and v2 not in v1:
            return False
    return True


# ── Shared iteration helper ────────────────────────────────────────────────────

def _cross_concept_pairs(system_nodes, user_nodes):
    """
    Yield (sys_node, user_node, w1, w2) for every system/user node pair where:
      - concepts differ (and base words differ)
      - args are compatible (subset relation + substring value match)
    """
    for user_node in user_nodes.values():
        for sys_node in system_nodes.values():
            if sys_node.concept == user_node.concept:
                continue
            if not _args_compatible(_args(sys_node), _args(user_node)):
                continue
            w1 = _base_concept(sys_node.concept)
            w2 = _base_concept(user_node.concept)
            if w1 == w2:
                continue
            yield sys_node, user_node, w1, w2


# ── Rule 5 helpers ─────────────────────────────────────────────────────────────

def _split_amr_trees(amr_str: str) -> list[str]:
    """Split a multi-tree Penman string into individual top-level tree strings."""
    trees, depth, start = [], 0, None
    for i, ch in enumerate(amr_str):
        if ch == '(':
            if depth == 0:
                start = i
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0 and start is not None:
                trees.append(amr_str[start:i + 1])
                start = None
    return trees


def _policy_positive_templates(policy_amr: str) -> list[str]:
    """
    Return a positive-action template for every prohibition tree (:polarity -)
    in the policy AMR. Strips the polarity annotation and inlines the bare
    cross-reference variable 's' (__system) so each template is self-contained.
    """
    templates = []
    for tree_str in _split_amr_trees(policy_amr):
        if ':polarity -' not in tree_str:
            continue
        t = re.sub(r'\s*:polarity\s+-', '', tree_str)
        # Inline bare cross-ref 's' (the __system node declared in the first tree)
        t = re.sub(r'(:ARG\w+)\s+s\b(?!\s*/)', r'\1 (s / __system)', t)
        templates.append(t)
    return templates


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
            if sys_pol != user_pol and _args_compatible(_args(sys_node), _args(user_node)):
                mismatches.append({
                    'predicate':       user_node.concept,
                    'system_polarity': sys_pol,
                    'user_polarity':   user_pol,
                    'args':            _args(sys_node),
                    'authorized':      _auth(user_node),
                })

    return mismatches


def detect_predicate_contradiction(system_amr, user_amr, relation_fn=None):
    """
    Rule (2+4): Different predicates with compatible args where the semantic
    relation between them — combined with polarity — signals a contradiction.

      synonym  + opposite polarity  →  same action negated            → contradiction
      antonym  + same    polarity   →  opposite actions, same sign
                                       (e.g. not-reveal vs not-hide)  → contradiction

    Both cases reduce to: the net semantic intent of the two predicates differs.

    relation_fn: callable(w1, w2) -> _RelationResult.
    Defaults to _classify_relation_llm. Pass a stub in tests to avoid API calls.

    Returns a list of dicts:
        {system_predicate, user_predicate, relation, system_polarity, user_polarity, args}
    """
    if relation_fn is None:
        relation_fn = _classify_relation_llm

    system_nodes = penman_to_dag(system_amr)
    user_nodes   = penman_to_dag(user_amr)

    results = []
    for sys_node, user_node, w1, w2 in _cross_concept_pairs(system_nodes, user_nodes):
        r = relation_fn(w1, w2)
        if r.score < SCORE_THRESHOLD or r.relation == 'none':
            continue
        sys_pol        = _polarity(sys_node)
        user_pol       = _polarity(user_node)
        polarity_match = (sys_pol == user_pol)
        if (r.relation == 'synonym' and not polarity_match) or \
           (r.relation == 'antonym' and     polarity_match):
            results.append({
                'system_predicate': sys_node.concept,
                'user_predicate':   user_node.concept,
                'relation':         r.relation,
                'system_polarity':  sys_pol,
                'user_polarity':    user_pol,
                'args':             _args(sys_node),
                'authorized':       _auth(user_node),
            })

    return results


def detect_policy_violation_smatch(
    system_amr: str,
    user_amr: str,
    threshold: float = 0.35,
) -> list[dict]:
    """
    Rule 5: Smatch recall against policy prohibition templates.

    For each prohibition tree in system_amr strip ':polarity -' to form a
    positive-action template T.  For each tree in user_amr compute smatch
    recall = best_match / gold_triples (how well user tree covers T).
    Return a violation dict when recall >= threshold.

    High recall means the output is structurally close to a prohibited action.
    No LLM calls required. Nodes with ':auth t' are treated as authorized.
    """
    try:
        import smatch
    except ImportError:
        return []

    templates = _policy_positive_templates(system_amr)
    user_trees = _split_amr_trees(user_amr)

    violations = []
    for template in templates:
        for user_tree_str in user_trees:
            authorized = ':auth t' in user_tree_str
            try:
                best_match, test_triples, gold_triples = smatch.get_amr_match(
                    user_tree_str, template
                )
                if gold_triples == 0:
                    continue
                recall = best_match / gold_triples
                _dbg(f"rule5 smatch: recall={recall:.3f} threshold={threshold}")
                if recall >= threshold:
                    violations.append({
                        'rule':            'rule5',
                        'recall':          round(recall, 3),
                        'policy_template': template.strip(),
                        'user_tree':       user_tree_str.strip(),
                        'authorized':      authorized,
                    })
            except Exception as e:
                _dbg(f"rule5 smatch error: {e}")
    return violations


def run_firewall_rules(
    system_amr: str,
    user_amr: str,
    active_rules: list | None = None,
    rule5_threshold: float = 0.35,
) -> list[dict]:
    """
    Dispatcher: run the selected detection rules and return a combined match list.
    active_rules defaults to ["rule1", "rule24"] when None.
    Accepted values: "rule1", "rule24", "rule5".
    """
    if active_rules is None:
        active_rules = ["rule1", "rule24"]
    results: list[dict] = []
    if "rule1" in active_rules:
        results += detect_polarity_mismatches(system_amr, user_amr)
    if "rule24" in active_rules:
        results += detect_predicate_contradiction(system_amr, user_amr)
    if "rule5" in active_rules:
        results += detect_policy_violation_smatch(system_amr, user_amr, rule5_threshold)
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


