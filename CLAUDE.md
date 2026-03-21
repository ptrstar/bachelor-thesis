# Bachelor Thesis — Semantic Firewall for LLM Prompt Injection

## Project Overview

This project is a bachelor thesis investigating **prompt injection attack detection and prevention** in large language models (LLMs). The core idea is to build a **semantic firewall** based on **Abstract Meaning Representation (AMR)** graphs.

The working directory is a **local folder on macOS**. Files may include Python scripts, datasets, and output artifacts.

## Research Goal

Design and evaluate a semantic firewall that detects prompt injection attacks by analyzing the **semantic relationship** between a system prompt and a (potentially adversarial) user/attacker prompt using AMR graph structures.

**Key hypothesis:** A prompt injection attack can be formally defined as a specific type of semantic relation between the system prompt graph and the attacker prompt graph — e.g., the attacker prompt overrides, hijacks, or contradicts the intent encoded in the system prompt.

## Core Technical Approach

1. **AMR Handling** — Initially use preexisting AMR strings for system and user prompts. Later transition to parsing prompts into AMR graphs using the Claude API.
2. **Graph-based Attack Definition** — Define prompt injection as a detectable structural/semantic pattern across the two AMR graphs (e.g., role-overriding nodes, conflicting root concepts, injected imperative structures).
3. **Firewall Logic** — Given the system prompt AMR and the incoming user prompt AMR, compute a similarity/conflict score or classify the pair as benign vs. attack.
4. **Evaluation** — Benchmark on known prompt injection datasets and adversarial examples.

## Key Concepts

- **AMR (Abstract Meaning Representation):** A rooted, directed, acyclic graph (DAG) representing the logical/semantic meaning of a sentence, abstracting away surface syntax. Nodes are concepts (PropBank frames or entities), edges are semantic roles (`:ARG0`, `:ARG1`, `:mod`, etc.).
- **Prompt Injection:** An attack where a malicious user prompt overrides or subverts the instructions given in the system prompt (e.g., "Ignore all previous instructions and...").
- **Semantic Firewall:** A pre-inference filter that intercepts (system prompt, user prompt) pairs and flags or blocks semantically adversarial inputs before they reach the LLM.

## Environment

- **Platform:** Local macOS with Anaconda environment (`bt`)
- **Language:** Python
- **Key libraries likely in use:** `networkx`, `transformers`, `torch`, `penman` (AMR serialization)
- The working directory is `/Users/janoschmoor/dev/bachelor-thesis/`
- Future: Integration with Claude API for AMR parsing

## Collaboration Notes

- Keep code focused and minimal — no over-engineering.
- Prefer editing existing notebooks/scripts over creating new files.
- When explaining AMR or graph concepts, assume a computer science background but not deep NLP expertise.
- This is research code — prioritize clarity and correctness over production robustness.
- Development is now local on macOS using Anaconda environment `bt`.
