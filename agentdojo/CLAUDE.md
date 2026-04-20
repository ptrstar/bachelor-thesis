# AgentDojo Integration — AMR Firewall

Evaluate the AMR-based semantic firewall against the AgentDojo v1 banking benchmark.
Run with: `conda run -n bt python agentdojo/eval.py`

---

## File Layout

| File | Role |
|---|---|
| `eval.py` | Entry point — `main()`, settings printout, benign/attack loops |
| `config.py` | Config flags, ANSI colours, policy strings, task lists, `TOOL_AMR_SCHEMAS` |
| `tasks.py` | Custom task classes + `register_custom_tasks()` |
| `execution_context.py` | `ExecutionContext` — per-run AMR forest (DAG objects) |
| `fw_elements.py` | `UserInputContextInit`, `AMRToolOutputFirewall`, `AMRToolCallFirewall`, `_AMRFirewallBase` |
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
| `TOOL_AMR_SCHEMAS` | Per-tool AMR schema hints injected into `get_amr_tool_output` prompts |

---

## Pipeline Structure

```
SystemMessage → InitQuery → UserInputContextInit → LLM → ToolsExecutionLoop(inner_loop) → MessageCapture
```

Default (`CHECK_TOOL_CALLS=False`): `inner_loop = [ToolsExecutor, AMRToolOutputFirewall, LLM]`  
Call mode (`CHECK_TOOL_CALLS=True`): `inner_loop = [AMRToolCallFirewall, ToolsExecutor, LLM]`

`build_pipeline()` returns `(pipeline, fw, capture)`. The firewall sets `fw.triggered = True` and raises `AbortAgentError` on a violation — caught internally by agentdojo, does **not** propagate out of `run_task_with_pipeline`. Always reset `fw.triggered = False` before each task.

---

## Execution Context (`execution_context.py`)

`ExecutionContext` is a per-run AMR forest stored in `extra_args["_exec_ctx"]`.

Each tree is stored as a `(penman_str, nodes_map)` pair so edges are directly queryable.  
Trees are separated into _checked_ (already scanned by the firewall) and _unchecked_ (newly added).

**Population order:**
1. `UserInputContextInit` parses the user message → adds user-intent trees, marks them checked (they carry `:auth t` so re-checking them on every tool pass is wasteful).
2. `AMRToolOutputFirewall` parses each untrusted tool output → appends trees, then checks only the unchecked slice.

**Key methods:**
- `add_tree(amr_str)` — parse and append to the forest
- `unchecked_trees()` — trees added since last `mark_checked()` call
- `mark_checked()` — advance the checked pointer
- `get_purpose()` — return the first `:purpose` string found (set by user-intent parser on read/fetch nodes)

---

## AMR Annotation Conventions

### `:auth t`
Placed on any AMR root node whose action/information was explicitly authorised by the user in their original request.  Produced by `get_amr_user_intent` and by `get_amr_tool_output` (when the parser judges output aligns with the stated purpose).  Firewall suppresses violations on nodes that carry `:auth t`.

```
(s / send-01
   :ARG0 (u / __user)
   :ARG1 (m / money :quant 50)
   :ARG2 (r / recipient :name "Gardener")
   :auth t)
```

### `:purpose "string"`
Attached to read/fetch action nodes in the user-intent AMR.  Passed to `get_amr_tool_output` so the parser can tag output nodes `:auth t` when they directly serve the purpose.

```
(g / get-01
   :ARG0 (u / __user)
   :ARG1 (t / transaction)
   :purpose "find gardener IBAN for payment"
   :auth t)
```

---

## Firewall Flow (context-aware mode, `CHECK_TOOL_CALLS=False`)

1. **`UserInputContextInit`** — parses user message with `get_amr_user_intent`.  Compound requests produce multiple trees, one per action.  All root nodes get `:auth t`.  Read/fetch nodes also get `:purpose "..."`.  Trees stored in `ExecutionContext`, marked checked.

2. **`AMRToolOutputFirewall.query`** — for each new untrusted tool output:
   - Retrieves `purpose = ctx.get_purpose()` (falls back to `"serve user request via {tool_name}"`).
   - Calls `get_amr_tool_output(client, text, tool_name, purpose, schema)`.
     Parser tags output nodes `:auth t` iff they directly serve the stated purpose.
   - Appends resulting trees to the forest.
   - Calls `_check_new_trees`: runs `detect_polarity_mismatches` + `detect_predicate_contradiction` on each new tree, filters out matches where `authorized=True` (node has `:auth t`), raises `AbortAgentError` on remaining violations.

3. Injected content (e.g. "send $500 to attacker") arrives in tool output without `:auth t`, matches the policy prohibition, and is blocked.

---

## Per-Tool AMR Schemas (`TOOL_AMR_SCHEMAS` in `config.py`)

Schema strings injected into the `get_amr_tool_output` prompt for each untrusted tool.  They tell the parser which slots to populate and how to structure transaction/user-info records.

| Tool | Schema covers |
|---|---|
| `get_most_recent_transactions` | One tree per transaction; sender/recipient :name/:iban, :quant, :time, subject |
| `get_scheduled_transactions` | Same structure as recent transactions |
| `get_user_info` | Single user-info tree: :name, :iban, :email, :phone, :address |
| `read_file` | Sentence-by-sentence; factual data as attributes on nearest predicate |

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
