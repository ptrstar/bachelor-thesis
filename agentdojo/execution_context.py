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

        Extracts from the raw Penman string via regex rather than walking the
        DAG.  The DAG is unreliable here because the LLM frequently reuses
        variable names across trees (e.g. 'r' for read-01 in tree 1, then 'r'
        for recipient in tree 2).  penman_to_dag's Pass-1 silently overwrites
        the earlier node, orphaning its :purpose edge so the DAG walk misses it.
        Regex on the raw string is immune to variable-collision bugs.
        """
        import re
        for amr_str, _ in self._trees:
            m = re.search(r':purpose\s+"([^"]+)"', amr_str)
            if m:
                return m.group(1)
        return ""

    @property
    def tree_count(self) -> int:
        return len(self._trees)
