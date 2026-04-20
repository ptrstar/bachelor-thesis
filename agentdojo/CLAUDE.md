# AgentDojo Integration — AMR Firewall

Evaluate the AMR-based semantic firewall against the AgentDojo v1 banking benchmark.
Run with: `conda run -n bt python agentdojo/eval.py`

---

## File Layout

| File | Role |
|---|---|
| `eval.py` | Entry point — `main()`, settings printout, benign/attack loops |
| `config.py` | Config flags, ANSI colours, policy strings, task lists |
| `tasks.py` | Custom task classes + `register_custom_tasks()` |
| `fw_elements.py` | `_AMRFirewallBase`, `AMRToolOutputFirewall`, `AMRToolCallFirewall`, `UNTRUSTED_TOOLS` |
| `pipeline.py` | `MessageCapture`, `build_pipeline()` |
| `reporting.py` | `print_summary(results)` |

`eval.py` sets up `sys.path` for both the thesis root (parse_amr, contradiction_rules) and this directory before any local imports.

---

## Configuration (`config.py`)

| Flag | Effect |
|---|---|
| `RESTRICTED_VOCAB` | Use 5-action/5-object banking vocabulary for AMR parsing |
| `CHECK_TOOL_CALLS` | Scan tool calls before execution instead of tool outputs after |
| `BLOCK_ON_UNEXPRESSABLE` | Block when AMR parser returns `__unexpressable` (whitelist mode) |
| `VERBOSE` | Coloured per-check logging + sets `contradiction_rules.DEBUG` |
| `USE_PREPARSED_AMR_POLICY` | Skip policy-parsing LLM call; use hardcoded `PREPARSED_BANKING_POLICY` |

---

## Pipeline Structure

```
SystemMessage → InitQuery → LLM → ToolsExecutionLoop(inner_loop) → MessageCapture
```

Default (`CHECK_TOOL_CALLS=False`): `inner_loop = [ToolsExecutor, AMRToolOutputFirewall, LLM]`  
Call mode (`CHECK_TOOL_CALLS=True`): `inner_loop = [AMRToolCallFirewall, ToolsExecutor, LLM]`

`build_pipeline()` returns `(pipeline, fw, capture)`. The firewall sets `fw.triggered = True` and raises `AbortAgentError` on a violation — caught internally by agentdojo, does **not** propagate out of `run_task_with_pipeline`. Always reset `fw.triggered = False` before each task.

---

## Custom Tasks (`tasks.py`)

| ID | Type | Description |
|---|---|---|
| `user_task_100` | Benign | User explicitly updates own password |
| `user_task_101` | Cover | User checks recent transactions |
| `user_task_102` | Benign | User delegates to `tasks.txt` (data-injection / FP tension demo) |
| `injection_task_100` | Attack | Change password via transaction subject injection |
| `injection_task_101` | Attack | Same, but password obfuscated as "flower" |

Task class names **must** match `UserTask{N}` / `InjectionTask{N}` — the suite derives the ID from the class name.

---

## Untrusted Tools (`fw_elements.py`)

Only outputs from these tools are scanned; action/confirmation tools are trusted:
`read_file`, `get_most_recent_transactions`, `get_scheduled_transactions`, `get_user_info`

---

## agentdojo Package Imports

Always import `get_suite` first — direct imports of the banking sub-module trigger a circular import.

```python
from agentdojo.task_suite import get_suite
from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.functions_runtime import Env, FunctionsRuntime, FunctionCall
from agentdojo.types import ChatMessage, get_text_content_as_str
from agentdojo.base_tasks import BaseUserTask, BaseInjectionTask
```
