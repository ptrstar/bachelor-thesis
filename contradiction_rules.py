from amr_graph import Node, penman_to_dag


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
