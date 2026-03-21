import penman


class Node:
    def __init__(self, variable, concept):
        self.variable = variable
        self.concept = concept
        self.edges = []

    def __repr__(self):
        return f"Node(variable={self.variable}, concept={self.concept})"


class Edge:
    def __init__(self, source_node, relation, target):
        self.source_node = source_node
        self.relation = relation
        self.target = target

    def __repr__(self):
        target_repr = self.target.variable if isinstance(self.target, Node) else repr(self.target)
        return f"Edge(source={self.source_node.variable}, relation={self.relation}, target={target_repr})"


def penman_to_dag(amr_string):
    g = penman.decode(amr_string)
    nodes_map = {}

    for source, relation, target in g.triples:
        if relation == ':instance':
            nodes_map[source] = Node(source, target)

    for source, relation, target in g.triples:
        if relation != ':instance':
            source_node = nodes_map.get(source)
            if source_node:
                target_obj = nodes_map.get(target, target)
                source_node.edges.append(Edge(source_node, relation, target_obj))

    return nodes_map


def draw_amr(amr_string):
    from graphviz import Digraph
    g = penman.decode(amr_string)
    dot = Digraph(comment='AMR Graph')
    dot.attr(rankdir='TB', size='8,8')
    dot.attr('node', shape='ellipse', style='filled', color='lightblue', fontname='Arial')

    instance_map = {}
    for source, role, target in g.triples:
        if role == ':instance':
            instance_map[source] = target
            dot.node(source, label=f"{source} / {target}")

    for source, role, target in g.triples:
        if role != ':instance':
            if target in instance_map:
                dot.edge(source, target, label=role)
            else:
                literal_id = f"lit_{source}_{role}_{target}"
                dot.node(literal_id, label=str(target), shape='none', style='plain')
                dot.edge(source, literal_id, label=role)

    return dot
