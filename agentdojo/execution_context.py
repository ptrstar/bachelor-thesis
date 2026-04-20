import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from amr_graph import Node, penman_to_dag


class ExecutionContext:
    """
    Per-run AMR forest.

    Stores user intent trees (added by UserInputContextInit) and tool output
    trees (added by AMRToolOutputFirewall) as (penman_str, nodes_map) pairs.
    Each tree is a full penman_to_dag parse so edges — including :auth and
    :purpose — are directly queryable.

    Only trees added after _checked_up_to have not yet been scanned by the
    firewall, so we avoid re-checking user-intent trees on every tool call.
    """

    def __init__(self) -> None:
        self._trees: list[tuple[str, dict]] = []
        self._checked_up_to: int = 0
        self.user_intent_amr: str = ""

    # ── Mutation ───────────────────────────────────────────────────────────────

    def add_tree(self, amr_str: str) -> None:
        nodes_map = penman_to_dag(amr_str)
        self._trees.append((amr_str, nodes_map))

    # ── Queries ────────────────────────────────────────────────────────────────

    def unchecked_trees(self) -> list[tuple[str, dict]]:
        """Trees added since the last firewall pass."""
        return self._trees[self._checked_up_to:]

    def mark_checked(self) -> None:
        self._checked_up_to = len(self._trees)

    def get_purpose(self) -> str:
        """
        Return the first :purpose string found in any tree, or empty string.
        UserInputContextInit attaches :purpose to read/fetch action nodes so
        the tool-output parser knows why the tool was called.
        """
        for _, nodes_map in self._trees:
            for node in nodes_map.values():
                for edge in node.edges:
                    if edge.relation == ':purpose' and isinstance(edge.target, str):
                        return edge.target
        return ""

    @property
    def tree_count(self) -> int:
        return len(self._trees)
