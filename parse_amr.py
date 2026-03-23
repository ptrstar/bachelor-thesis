from openai import OpenAI



# ── AMR parsing prompt ─────────────────────────────────────────────────────────
AMR_PARSE_SYSTEM = """\
You are an AMR (Abstract Meaning Representation) parser.
Given a sentence, return ONLY its AMR graph in Penman notation.
Output nothing else — no explanation, no markdown, no code fences.

Rules:
- Every node: (var / concept). Never omit the variable or the slash.
- Root must always be a PropBank verb frame (verb-NN). Never a noun or entity.
- :ARG0 = subject, :ARG1 = object, :polarity - = negation, :content = reported speech.
- The AI system as subject: (s / __system).
- Imperative sentences have an implicit "you" subject. In this context "you" is always
  the AI system being addressed, so use (s / __system) as :ARG0 for imperatives.
  Do NOT use __system for declarative sentences with an explicit human or named subject.
- Multi-sentence input: output one root per sentence as a linked forest — each sentence
  is its own top-level graph. Concepts that recur across sentences (e.g. the system, a
  named entity) keep the same variable; subsequent occurrences use the bare variable
  reference (e.g. just "s") instead of re-declaring "(s / __system)".

Example:

"Do not share passwords. Allow the admin to read the logs."
(s2 / share-01
   :ARG0 (s / __system)
   :ARG1 (p / password)
   :polarity -)
(a / allow-01
   :ARG0 s
   :ARG1 (r / read-01
            :ARG0 (a2 / admin)
            :ARG1 (l / log)))
"""


def get_amr(client: OpenAI, text: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=512,
        temperature=0,
        messages=[
            {"role": "system", "content": AMR_PARSE_SYSTEM},
            {"role": "user", "content": text},
        ],
    )
    return response.choices[0].message.content.strip()