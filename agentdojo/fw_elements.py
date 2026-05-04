from collections.abc import Sequence

import openai

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.functions_runtime import Env, FunctionsRuntime, FunctionCall
from agentdojo.types import ChatMessage, get_text_content_as_str

from parse_amr import get_amr, get_amr_user_intent, get_amr_tool_output, standardize_user_input, is_unexpressable
from execution_context import ExecutionContext
from agentdojo.types import text_content_block_from_string as _text_block
from config import _RED, _GREEN, _YELLOW, _CYAN, _GRAY, _BOLD, _RESET, TOOL_AMR_SCHEMAS

def _log_match(m: dict, red: str, reset: str) -> None:
    """Print a single firewall rule match to stdout."""
    rule = m.get('rule')
    if rule == 'rule5':
        print(f"    {red}rule5:   recall={m['recall']:.3f} "
              f"[auth={m.get('authorized')}] → smatch policy match{reset}")
    elif "user_predicate" in m:
        print(f"    {red}rule2+4: {m['system_predicate']} ({m['system_polarity']}) "
              f"vs {m['user_predicate']} ({m['user_polarity']}) — {m['relation']} "
              f"[auth={m.get('authorized')}] → contradiction{reset}")
    else:
        print(f"    {red}rule1:   {m['predicate']} "
              f"sys={m['system_polarity']} user={m['user_polarity']} "
              f"[auth={m.get('authorized')}] → polarity mismatch{reset}")


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


# ── Shared base ────────────────────────────────────────────────────────────────

class _AMRFirewallBase(BasePipelineElement):
    """Shared init and _check_text logic for both firewall variants."""

    def __init__(
        self,
        client: openai.OpenAI,
        system_amr: str,
        restricted_vocab: bool = False,
        block_on_unexpressable: bool = False,
        verbose: bool = False,
        amr_replace_outputs: bool = False,
        active_rules: list | None = None,
        rule5_threshold: float = 0.35,
    ) -> None:
        self.client = client
        self.system_amr = system_amr
        self.restricted_vocab = restricted_vocab
        self.block_on_unexpressable = block_on_unexpressable
        self.verbose = verbose
        self.amr_replace_outputs = amr_replace_outputs
        self.active_rules = active_rules if active_rules is not None else ["rule1", "rule24"]
        self.rule5_threshold = rule5_threshold
        self.triggered = False        # set True when AbortAgentError is raised; reset per task in main()
        self.trigger_details: list[dict] = []  # violation match dicts from the last triggered block

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
            matches = cr.run_firewall_rules(
                self.system_amr, user_amr,
                self.active_rules, self.rule5_threshold,
            )
        except Exception as e:
            if self.verbose:
                print(f"    {_GREEN}✓ PASS — rule check error ({type(e).__name__}: {e}){_RESET}")
            return

        if matches:
            if self.verbose:
                for m in matches:
                    _log_match(m, _RED, _RESET)
                print(f"    {_RED}{_BOLD}✗ BLOCKED{_RESET}")
            self.triggered = True
            self.trigger_details = matches
            raise AbortAgentError("Firewall: policy violation detected.", messages, env)

        if self.verbose:
            print(f"    {_GREEN}✓ PASS — no policy match{_RESET}")


# ── Tool-call firewall (stateless, pre-execution) ──────────────────────────────

class AMRToolCallFirewall(_AMRFirewallBase):
    """
    Checks tool CALLS before execution (CHECK_TOOL_CALLS=True).
    Converts each pending FunctionCall to natural language and runs the AMR check.
    Remains stateless — does not use the execution context.
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


# ── User-input context initialiser ────────────────────────────────────────────

class UserInputContextInit(BasePipelineElement):
    """
    Runs once, before the first LLM call.

    Parses the user's message into an AMR forest using the intent-aware prompt
    (CONTEXT_USER_INTENT).  Each distinct action becomes its own tree with
    :auth t on the root.  Read/fetch actions carry :purpose "..." so the
    tool-output parser later knows why the tool was called.

    Stores the resulting ExecutionContext in extra_args["_exec_ctx"].
    """
    name = "user_input_context_init"

    def __init__(self, client: openai.OpenAI, verbose: bool = False) -> None:
        self.client = client
        self.verbose = verbose

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env,
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        ctx = ExecutionContext()

        user_msg = next((m for m in messages if m["role"] == "user"), None)
        if user_msg is not None:
            raw_text = get_text_content_as_str(user_msg["content"])
            standardized = standardize_user_input(self.client, raw_text)
            intent_amr = get_amr_user_intent(self.client, standardized)
            ctx.user_intent_amr = intent_amr

            if not is_unexpressable(intent_amr):
                ctx.add_tree(intent_amr)
                # user intent trees are pre-authorised — mark them as already checked
                # so the firewall does not re-scan them on every tool-output pass
                ctx.mark_checked()

            if self.verbose:
                print(f"\n  {_YELLOW}{_BOLD}▶ CTX-INIT{_RESET} standardized: {standardized!r}")
                print(f"  {_YELLOW}{_BOLD}▶ CTX-INIT{_RESET} user intent AMR:")
                for line in intent_amr.strip().splitlines():
                    print(f"    {_CYAN}{line}{_RESET}")

        return query, runtime, env, messages, {**extra_args, "_exec_ctx": ctx}


# ── Tool-output firewall (context-aware, post-execution) ──────────────────────

class AMRToolOutputFirewall(_AMRFirewallBase):
    """
    Checks tool OUTPUTS after execution (CHECK_TOOL_CALLS=False).

    For each untrusted tool output:
      1. Parse with purpose context + per-tool schema → AMR tree(s).
         Nodes serving the stated purpose are tagged :auth t by the parser.
      2. Insert every resulting tree into the ExecutionContext forest.
      3. Check only the newly inserted trees against the system policy.
         Matches where the violating node carries :auth t are suppressed
         (the user explicitly authorised that action).

    Falls back to the stateless _check_text path when no context is available
    (e.g. CHECK_TOOL_CALLS=True pipeline that skips UserInputContextInit).
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
        ctx: ExecutionContext | None = extra_args.get("_exec_ctx")
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

            if ctx is None:
                # No execution context — fall back to stateless check
                self._check_text("tool_output", text, env, list(messages))
                continue

            # ── Context-aware path ─────────────────────────────────────────
            purpose    = ctx.get_purpose() or f"serve user request via {tool_name}"
            schema     = TOOL_AMR_SCHEMAS.get(tool_name, "")
            output_amr = get_amr_tool_output(self.client, text, tool_name, purpose, schema)

            if self.verbose:
                print(f"       {_CYAN}purpose: {purpose!r}{_RESET}")
                print(f"       {_CYAN}amr:{_RESET}")
                for line in output_amr.strip().splitlines():
                    print(f"       {_CYAN}{line}{_RESET}")

            if is_unexpressable(output_amr):
                if self.block_on_unexpressable:
                    if self.verbose:
                        print(f"       {_RED}✗ BLOCKED — unexpressable (whitelist mode){_RESET}")
                    self.triggered = True
                    raise AbortAgentError("Firewall: unexpressable tool output.", list(messages), env)
                if self.verbose:
                    print(f"       {_GREEN}✓ PASS — unexpressable, treated as benign{_RESET}")
                continue

            if self.amr_replace_outputs:
                msg["content"] = [_text_block(output_amr)]
                print(f"       {_CYAN}↳ LLM sees: AMR (Penman){_RESET}")
            else:
                print(f"       {_GRAY}↳ LLM sees: raw YAML{_RESET}")

            ctx.add_tree(output_amr)
            self._check_new_trees(ctx, env, list(messages))

        extra_args = {**extra_args, "_fw_scanned": len(messages)}
        return query, runtime, env, messages, extra_args

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _check_new_trees(self, ctx: ExecutionContext, env: Env, messages: list) -> None:
        """
        Run the policy rules against each tree added since the last check.
        Violations with :auth t on the user-side node are suppressed —
        the action was explicitly requested by the user.
        """
        import contradiction_rules as cr

        violations = []
        for amr_str, _ in ctx.unchecked_trees():
            if not amr_str.strip():
                continue
            try:
                matches = cr.run_firewall_rules(
                    self.system_amr, amr_str,
                    self.active_rules, self.rule5_threshold,
                )
            except Exception as e:
                if self.verbose:
                    print(f"    {_GREEN}✓ PASS — rule check error ({type(e).__name__}: {e}){_RESET}")
                continue
            for m in matches:
                if not m.get('authorized', False):
                    violations.append(m)

        ctx.mark_checked()

        if violations:
            if self.verbose:
                for m in violations:
                    _log_match(m, _RED, _RESET)
                print(f"    {_RED}{_BOLD}✗ BLOCKED{_RESET}")
            self.triggered = True
            self.trigger_details = violations
            raise AbortAgentError("Firewall: policy violation detected.", messages, env)

        if self.verbose:
            print(f"    {_GREEN}✓ PASS — no unauthorized policy match{_RESET}")
