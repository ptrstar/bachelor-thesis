from collections.abc import Sequence

import openai

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.functions_runtime import Env, FunctionsRuntime, FunctionCall
from agentdojo.types import ChatMessage, get_text_content_as_str

from parse_amr import get_amr, is_unexpressable
from config import _RED, _GREEN, _YELLOW, _CYAN, _GRAY, _BOLD, _RESET

# Tools whose outputs may contain attacker-controlled free text.
# Action/confirmation tools are excluded — their outputs are structured/trusted.
UNTRUSTED_TOOLS = {
    "read_file",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "get_user_info",
}


def _tool_call_to_text(fc: FunctionCall) -> str:
    """Convert a FunctionCall to a short natural-language sentence for AMR parsing."""
    name = fc.function
    args = fc.args
    if name == "send_money":
        return f"Send {args.get('amount', 'money')} to account {args.get('recipient', 'recipient')}."
    if name == "schedule_transaction":
        return f"Schedule sending {args.get('amount', 'money')} to account {args.get('recipient', 'recipient')}."
    if name == "update_password":
        return "Change the user password to a new value."
    if name == "update_user_info":
        return "Change the user account information."
    if name == "update_scheduled_transaction":
        return "Modify the recipient or amount of a scheduled transaction."
    if name == "get_balance":
        return "Get the account balance."
    if name == "get_iban":
        return "Get the account IBAN."
    if name == "get_most_recent_transactions":
        return "Get the recent transaction history."
    if name == "get_scheduled_transactions":
        return "Get the list of scheduled transactions."
    if name == "get_user_info":
        return "Get the user account information."
    if name == "read_file":
        return f"Read the file {args.get('file_path', '')}."
    return f"Execute {name} with arguments {dict(args)}."


class _AMRFirewallBase(BasePipelineElement):
    """Shared init and _check_text logic for both firewall variants."""

    def __init__(
        self,
        client: openai.OpenAI,
        system_amr: str,
        restricted_vocab: bool = False,
        block_on_unexpressable: bool = False,
        verbose: bool = False,
    ) -> None:
        self.client = client
        self.system_amr = system_amr
        self.restricted_vocab = restricted_vocab
        self.block_on_unexpressable = block_on_unexpressable
        self.verbose = verbose
        self.triggered = False  # set True when AbortAgentError is raised; reset per task in main()

    def _check_text(self, label: str, text: str, env: Env, messages: list) -> None:
        """Parse text to AMR and compare against system policy. Raises AbortAgentError on violation."""
        import contradiction_rules as cr

        if self.verbose:
            print(f"  {_YELLOW}{_BOLD}▶ FIREWALL{_RESET} scanning [{label}]")

        is_tool = label == "tool_output"
        user_amr = get_amr(self.client, text, parsing_system=False,
                           restricted_vocab=self.restricted_vocab, tool_output=is_tool)

        if is_unexpressable(user_amr):
            if self.block_on_unexpressable:
                if self.verbose:
                    print(f"    {_CYAN}amr: (u / __unexpressable){_RESET}")
                    print(f"    {_RED}✗ BLOCKED — unexpressable (whitelist mode){_RESET}")
                self.triggered = True
                raise AbortAgentError("Firewall: input unexpressable under restricted vocabulary.", messages, env)
            if self.verbose:
                print(f"    {_CYAN}amr: (u / __unexpressable){_RESET}")
                print(f"    {_GREEN}✓ PASS — unexpressable, treated as benign (blacklist mode){_RESET}")
            return

        if self.verbose:
            print(f"    {_CYAN}amr:{_RESET}")
            for line in user_amr.strip().splitlines():
                print(f"    {_CYAN}{line}{_RESET}")

        try:
            r1  = cr.detect_polarity_mismatches(self.system_amr, user_amr)
            r24 = cr.detect_predicate_contradiction(self.system_amr, user_amr)
        except Exception as e:
            if self.verbose:
                print(f"    {_GREEN}✓ PASS — AMR parse error ({type(e).__name__}: {e}){_RESET}")
            return

        matches = r1 + r24
        if matches:
            if self.verbose:
                for m in matches:
                    if "user_predicate" in m:
                        print(f"    {_RED}rule2+4: {m['system_predicate']} ({m['system_polarity']}) "
                              f"vs {m['user_predicate']} ({m['user_polarity']}) — {m['relation']} → contradiction{_RESET}")
                    else:
                        print(f"    {_RED}rule1:   {m['predicate']} "
                              f"sys={m['system_polarity']} user={m['user_polarity']} "
                              f"args={m['args']} → polarity mismatch{_RESET}")
                print(f"    {_RED}{_BOLD}✗ BLOCKED{_RESET}")
            self.triggered = True
            raise AbortAgentError("Firewall: policy violation detected.", messages, env)

        if self.verbose:
            print(f"    {_GREEN}✓ PASS — no policy match{_RESET}")


class AMRToolCallFirewall(_AMRFirewallBase):
    """
    Checks tool CALLS before execution (CHECK_TOOL_CALLS=True).
    Converts each pending FunctionCall to natural language and runs the AMR check.
    """
    name = "amr_tool_call_firewall"

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env,
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        last = messages[-1] if messages else None
        if last is None or last["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        for fc in (last.get("tool_calls") or []):
            if self.verbose:
                print(f"  [{_BOLD}call{_RESET}] {fc.function}()")
            self._check_text(f"tool_call:{fc.function}", _tool_call_to_text(fc), env, list(messages))
        return query, runtime, env, messages, extra_args


class AMRToolOutputFirewall(_AMRFirewallBase):
    """
    Checks tool OUTPUTS after execution (CHECK_TOOL_CALLS=False).
    Only inspects outputs from UNTRUSTED_TOOLS.
    """
    name = "amr_tool_output_firewall"

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env,
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        already_scanned = extra_args.get("_fw_scanned", 0)
        new_messages = list(messages)[already_scanned:]

        if self.verbose and new_messages:
            print(f"\n  {_BOLD}── FW pass{_RESET} [{len(new_messages)} new msg{'s' if len(new_messages) != 1 else ''}]")

        for i, msg in enumerate(new_messages):
            role = msg["role"]
            idx  = already_scanned + i

            if self.verbose:
                if role == "tool":
                    tool_name = msg["tool_call"].function
                    trust_tag = f"{_RED}UNTRUSTED{_RESET}" if tool_name in UNTRUSTED_TOOLS else f"{_GREEN}trusted{_RESET}"
                    print(f"  [{idx}] tool:{tool_name} [{trust_tag}]")
                elif role == "assistant":
                    calls = msg.get("tool_calls") or []
                    desc  = f"<tool calls: {', '.join(fc.function for fc in calls)}>" if calls else "<no content>"
                    print(f"  [{idx}] assistant: {desc}")
                else:
                    raw     = msg.get("content")
                    preview = get_text_content_as_str(raw)[:80].strip() if raw else "<no content>"
                    print(f"  [{idx}] {role}: {preview!r}")

            if role != "tool":
                continue
            tool_name = msg["tool_call"].function
            if tool_name not in UNTRUSTED_TOOLS:
                continue
            text = get_text_content_as_str(msg["content"])
            if not text.strip():
                if self.verbose:
                    print(f"       {_GRAY}(empty output — skipped){_RESET}")
                continue

            if self.verbose:
                lines = text.splitlines()
                print(f"       {_GRAY}┌── raw output {'─' * 44}")
                for line in lines[:25]:
                    print(f"       │ {line}")
                if len(lines) > 25:
                    print(f"       │ ... ({len(lines) - 25} more lines)")
                print(f"       └{'─' * 52}{_RESET}")

            self._check_text("tool_output", text, env, list(messages))

        extra_args = {**extra_args, "_fw_scanned": len(messages)}
        return query, runtime, env, messages, extra_args
