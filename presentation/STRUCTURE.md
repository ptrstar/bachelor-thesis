# Presentation Plan — 20 min
## Semantic Firewall for LLM Prompt Injection

---

## Narrative Arc

Each slide earns the next one. The flow:

> Problem (what injection is, why current defenses fail)
> → we need a formal definition → work at the semantic level
> → AMR gives us that semantic substrate
> → now we can define injection formally
> → here's a concrete example
> → here's the system
> → here's the evaluation
> → here are the honest limits
> → summary

Never introduce a concept before motivating why it's needed.

---

## Slide-by-Slide Plan

### 1. Title

---

### 2. What is Prompt Injection? *(2 min — combined motivation + defense gap)*

- Indirect injection focus: the attacker is NOT the user. They control a file or
  DB record the agent reads while doing a legitimate task.
- One line distinguishing from jailbreaking (training vs. context window)
- Existing defenses:
  - Keyword filters: brittle, new phrasing defeats them
  - LLM-as-judge (the dominant approach): passes the adversarial text to a second
    LLM — Shi et al. (2024) show a sufficiently crafted injection can manipulate
    the judge itself. No formal guarantee.
- **Punchline:** no defense has a formal, auditable definition of *what injection is*.
  That's the gap.

---

### 3. Two Levels of Abstraction *(2 min — motivate semantic level)*

- Diagram: Task level T (raw strings) vs. Semantic level T' (AMR graphs)
- At the task level, injection is hard to define precisely — same attack can be
  phrased dozens of ways.
- At the semantic level, we can define it: a payload contradicts the policy graph.
- **Fix from v1:** don't claim wire/send "collapse" to the same predicate. Correct
  claim: AMR abstracts over syntactic variation. Synonymous verbs *may* map to
  different AMR predicates — that's not a bug, it's handled by synonym matching.
  Either way, the attacker's evasion surface shrinks. Say it that way.
- This slide sets up the question: "what's the semantic representation?" → next slide.

---

### 4. What is AMR? *(2 min — explain the tool)*

- Abstract Meaning Representation: a rooted, directed, acyclic graph for sentence meaning.
  Developed by linguists (Banarescu et al., 2013) for broad NLP tasks.
- Used in: abstractive summarization (Liu et al., 2018), question answering
  (Wang et al., 2023), LLM compliance checking (Chung et al., 2025).
- Show example graph for "Do not send money" — node, edges, polarity.
- Key insight for our purposes: predicate + polarity + arguments are all explicit
  and discrete. Syntactic paraphrase collapses; semantic content stays.

---

### 5. Semantic Definition of Injection *(3 min — the core contribution)*

- Definition: a payload P is a semantic injection w.r.t. policy S if the AMR of P
  contains a semantic contradiction with the AMR of S.
- **The process (important to explain this):**
  1. Parse policy once → get prohibition trees (nodes with :polarity -)
  2. For each tool output: parse → scan output nodes
  3. Deterministic argument check: does an output predicate have compatible
     arguments to any prohibition tree? (substring matching, explicit criterion)
  4. If yes: call GPT-4o-mini with exactly **two words** — base concept from policy,
     base concept from output. Classify: synonym / antonym / unrelated.
  5. Synonym + polarity flip → contradiction. Antonym + same polarity → contradiction.
- **Why this is hard to inject:** the attacker controls the tool output, so at most
  they control one of the two words. The policy word is fixed. A single word is not
  a meaningful attack surface against a model that returns a 3-way enum.
- This is the key contrast with LLM-as-judge: we never pass adversarial prose to a judge.

---

### 6. Worked Example *(3 min — make it concrete)*

- Show two policy prohibition trees: `send-01` (money) and `change-01` (password)
- Show injection AMR: `wire-01` with :ARG1 (money node with :iban and :quant)
- Walk through: argument compatibility check filters. `wire-01` has a money argument
  → compatible with `send-01` policy tree, not with `change-01`. Only the `send-01`
  pair proceeds to the LLM call.
- GPT-4o-mini: "wire" vs "send" → synonym → polarity flip (+/−) → BLOCK
- **TikZ improvements from v1:**
  - Make bigger, increase node sizes
  - Edge labels (:ARG0, :ARG1, :polarity) must be clearly readable
  - Add :iban and :quant to money node in injection AMR
  - Show both policy trees, grey out the non-matching one

---

### 7. Architecture *(2 min — clean and AMR-focused)*

- Clean linear flow, three steps:
  1. System policy → GPT-4o → Policy Graph (done once at startup)
  2. Tool output → GPT-4o → Output AMR
  3. Deterministic matcher → BLOCK or PASS
- Key emphasis: step 3 has no LLM in the hot path (except the 2-word call for
  synonym/antonym, which is bounded and injection-resistant)
- No auth annotation details — too much implementation detail for a presentation
- The AMR is what the agent sees (show that the raw JSON is replaced by AMR in
  the agent's context — brief mention, since it improves utility too)

---

### 8. AgentDojo Benchmark *(3 min — evaluation setup + concrete examples)*

- Banking benchmark: 101 attack pairs, 31 benign tasks, 10 injection categories
- Show **concrete examples** (user to provide):
  - One injection that was caught by the firewall: [USER TO PROVIDE]
  - One injection that was caught by the LLM but not the firewall: [USER TO PROVIDE]
  - One persistent miss (Category E): [USER TO PROVIDE]
- Purpose: show the audience what these attacks actually look like

---

### 9. Results + Comparison *(2 min)*

- Stacked bar chart (keep from v1): Baseline 83% combined → Firewall 97% combined
- Comparison table: this work vs. Abdelnabi et al. (2025)
  - Note clearly: different benchmarks, not a direct comparison
  - Differentiators: no training data, human-readable policy, interpretable blocking

**Abdelnabi et al. numbers from background chapter:**
- ConVerse benchmark, 864 attacks
- Privacy attacks: 84% → 10% success (= 16% → 90% defense rate)
- Security attacks: 60% → 3% success (= 40% → 97% defense rate)
- Method: structural protocol conversion (learns schema from well-formed messages;
  requires training data per deployment)

---

### 10. Limitations *(2 min)*

- AMR parser is non-deterministic → no end-to-end formal guarantee
- The guarantee lives at the matching layer, conditioned on parser output
- Broad-delegation boundary: user says "run tasks.txt" → auth is respected → a file
  attacker can modify defeats the firewall. Not a bug — fundamental scope limit.
- Low-abstraction attacks: "buy Tesla stocks" doesn't map to an antonym/synonym of
  any policy predicate

---

### 11. Takeaways *(1 min)*

- A system policy can be expressed as an AMR graph — concise, human-readable, inspectable
- Injection can be *defined* at the semantic level as predicate contradiction
- That definition is empirically meaningful: 97% combined stop rate, 3% miss
- The two-level framework cleanly separates what we formally claim from what we
  empirically demonstrate

---

## Language Checklist

Before finalising slides, check every sentence against this:
- Say "the results show" not "we demonstrate"
- Say "this catches" not "our approach is able to catch"
- Avoid hedge stacks ("we believe this approach may potentially...")
- No bullet that ends with "which is an important property"
- Direct active voice: "AMR discards word order" not "word order is discarded by AMR"

---

## Q&A Prep (Čapkun)

**"Your definition is circular."**
→ Yes, intentionally. A definition has to start somewhere. The question is whether
   it's meaningful — the benchmark says it is. And it's auditable in a way no
   LLM-based definition is.

**"Your parser is non-deterministic."**
→ The formal property lives at the matching step, conditioned on parser output.
   Same as a verified compiler: guarantees hold given a correct IR, not end-to-end.

**"Why AMR over embeddings?"**
→ Auditable, discrete, no threshold calibration, no training data, policy in one sentence.

**"What's your threat model?"**
→ Indirect injection: attacker controls content in a file or record the agent reads.
   We don't model adaptive attackers who know the firewall rules.

**"Category E misses?"**
→ The user delegated execution of the whole file. The firewall correctly respects that.
   The gap is between what the user said and what they meant — that's a different problem.
