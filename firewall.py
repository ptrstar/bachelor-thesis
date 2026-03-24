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


def check(client: OpenAI, system_amr: str, user_prompt: str) -> FirewallResult:
    """
    Parse user_prompt into AMR, run all detection rules against system_amr,
    and return a FirewallResult indicating whether the prompt is blocked.
    """
    user_amr = get_amr(client, user_prompt, parsing_system=False)
    matches  = cr.detect_semantic_similarity(system_amr, user_amr)
    return FirewallResult(blocked=bool(matches), user_amr=user_amr, matches=matches)