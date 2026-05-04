"""
Core firewall logic — import this anywhere that needs firewall functionality.
Returns structured data; printing/formatting is left to the caller.
"""

from dataclasses import dataclass, field
from openai import OpenAI
from parse_amr import get_amr
import contradiction_rules as cr


@dataclass
class FirewallResult:
    blocked: bool
    user_amr: str
    matches: list = field(default_factory=list)   # dicts from the rule that fired


def check(
    client: OpenAI,
    system_amr: str,
    user_prompt: str,
    active_rules: list | None = None,
    rule5_threshold: float = 0.35,
) -> FirewallResult:
    """
    Parse user_prompt into AMR, run the selected detection rules against system_amr,
    and return a FirewallResult indicating whether the prompt is blocked.

    active_rules: list of rule names to run (default: ["rule1", "rule24"]).
      "rule1"  — same predicate, opposite polarity
      "rule24" — different predicates (synonym/antonym) + polarity logic (LLM calls)
      "rule5"  — smatch recall against policy templates (no LLM calls)
    """
    user_amr = get_amr(client, user_prompt, parsing_system=False)
    matches = cr.run_firewall_rules(system_amr, user_amr, active_rules, rule5_threshold)
    return FirewallResult(blocked=bool(matches), user_amr=user_amr, matches=matches)