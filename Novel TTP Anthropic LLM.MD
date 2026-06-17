# MTDF Novel Threat Copilot — Setup Notes

## What this is

The 4th pillar of your MTDF AI Copilot Suite. Sits BEFORE Engineering and
Hunt in the pipeline — it's where you go when you have a threat name, a CVE,
a MITRE ID, or just a vague idea, and NOTHING built yet. It researches the
threat, builds the attack anatomy (Mermaid diagram + stage table), arrives
at a minimum truth statement, classifies it (Primitive/Router/Composite)
using your existing noise domain test, and hands off a Promotion Package
to whichever of your other three workspaces fits.

It does not replace Hunt Copilot. Hunt validates a hypothesis you already
have against your own telemetry. This one builds the hypothesis in the
first place when no prior detection content exists for the threat.

## AnythingLLM workspace setup

1. Create a new workspace: **MTDF Novel Threat Copilot**
2. System Prompt: paste the full contents of `MTDF_NovelThreat_SystemPrompt.md`
3. Model: Claude Sonnet 4.6
4. **Web search MUST be enabled** — this workspace cannot function without
   live research capability. This is the one prompt in your suite that
   structurally depends on it.
5. Chat history: 6 (matches Hunt Copilot — the 7-question arc needs context
   retention across multiple turns)
6. RAG documents to attach (optional but recommended):
   - MITRE ATT&CK STIX export (same one used elsewhere if you have it)
   - Your existing cousin ecosystem reference / decomposition trackers
     from the Engineering workspace, so this prompt can detect "this isn't
     actually novel, here's the existing cousin" at Q2

## How a session will actually flow

1. You answer Q1 with literally anything — a CVE, a MITRE ID, "I read about
   a new way to abuse X", a pasted advisory URL. All are valid.
2. Copilot researches it live, presents findings, asks you to confirm at Q2.
3. Copilot asks about POC/exploit availability at Q3.
4. Copilot builds the full attack anatomy — Mermaid flowchart, stage table,
   minimum truth candidate — and asks you to confirm/correct at Q4.
5. Copilot walks through telemetry surface at Q5, classifies Router vs
   Composite vs Primitive at Q6 using the same noise domain test as your
   other prompts, then asks where to hand off at Q7.
6. You get a Promotion Package shaped to drop straight into Engineering
   Copilot (skips its 12-question intake) or Hunt Copilot (skips its
   6-question intake).

Every single question along the way comes with a worked example specific
to YOUR threat, a one-line "why this matters" tied to MTDF doctrine, and an
explicit fallback if you don't know the answer. Pushback happens whenever
an answer is thin, contains inference language where it shouldn't, or
risks a ghost chain / blind spot — same standard as your Engineering prompt.

## Where this fits relative to your Hugging Face Space

The HF Space (MTDF-Copilot-v6, Streamlit, 3 tabs) is a separate deployment
of Engineering + Hunt + Atlas as an interactive demo. This 4th prompt is
currently AnythingLLM-only. If you want it as a 4th Streamlit tab later,
the question arc (one question per turn, dynamic content) needs the same
treatment we discussed for the Engineering Copilot port — state held across
turns, evaluated client-side, single Claude API call per turn rather than
the all-questions-at-once block the other three tabs use. That's a separate
build from this system prompt and not required to start using this in
AnythingLLM today.
