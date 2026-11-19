# AGENTS.md — how we work on AI-Sentinel

## Context
- The user is a B.Tech student with first-year coding knowledge. This is a graded capstone: they must run, understand and defend every line in a viva. Optimise for correctness and understanding, not speed or line count.
- Project scope lives in docs/paper.md. Architecture lives in docs/ARCHITECTURE.md (once it exists).

## Language
- Talk to me in simple Hinglish (Roman Hindi + English technical terms). Short sentences, small analogies.
- Code, comments, commit messages, README and everything in docs/ are in English, except docs/LEARNING_NOTES.md (Hinglish, one section per phase).

## The contract (this is what "not vibe-coded" means)
1. Plan before code. Each phase starts with a written plan: goal, files to touch, tests, risks, alternatives considered. Stop and wait for my "approved".
2. Phase gates. Finish one phase, show evidence, stop. Never start the next phase on your own.
3. Evidence, not claims. "Done" means you ran the tests/commands and pasted the real output. Never say something works without running it. If you could not run something, say so.
4. No invented numbers. Every metric comes from a script in the repo and is saved under results/ with dataset, seed, git commit and date. Report bad results as they are. Never tune on the test set; the test set is used once, in the evaluation phase.
5. No magic. Each non-obvious choice (algorithm, threshold, library, regex) gets an entry in docs/DECISIONS.md: context, options, choice, why, trade-off.
6. Small steps. One concern per commit; the message explains why. Do not touch unrelated files. No big rewrites without asking.
7. Never weaken a test to make it pass. If you think a test is wrong, explain and ask.
8. Simple over clever. Prefer the standard library and the existing stack. Every new dependency needs a pinned version and a one-line justification in docs/DECISIONS.md.
9. No fake completeness: no TODO stubs, no hard-coded results, no dead or commented-out code, no mock data presented as real. Anything unfinished or weak goes in docs/LIMITATIONS.md.
10. Teach-back. End every phase with (a) a 10-line plain explanation of what was built and why, and (b) 5 viva-style questions for me in chat. Wait for my answers, correct me, and put model answers in docs/VIVA_NOTES.md.
11. When unsure, ask one clear question. Do not guess silently.

## Code standards
- Python 3.11+. Type hints on public functions. A short docstring on every module saying what it is for and why it exists. Comments only where the "why" is not obvious.
- ruff (lint + format) and pytest must pass before you say a phase is done.
- Configuration in one place (config file + env vars). No secrets in code. Provide .env.example.
- SQL: parameterised queries only. Limit the size of all inputs. Escape all HTML output.
- Deterministic: fixed random seeds, pinned requirements, one command to reproduce each result.
- Work in a virtual environment. Ask before installing anything globally.

## Security-tool rules
- Lab only. Test traffic may target only localhost or this project's own local containers. Do not write code that can scan or attack other hosts; the traffic generator must refuse non-local targets. Use the browser tool only for http://127.0.0.1 / localhost pages.
- Never log secrets (passwords, tokens, cookies). Dashboard and API require authentication.
- Fail safe: if the ML part fails, the rule engine keeps working and the failure is logged. Every automatic block is reversible (TTL), has an allowlist, and can run in dry-run/monitor mode.
- ML alone never blocks. Blocking needs a rule match, or rule + ML agreement (policy from the paper).
- Never run destructive commands (rm -rf, git push --force, dropping a database) or push to a remote without asking.

## Scientific honesty
- Always report false-positive rate next to recall. State dataset limits (CSIC 2010: one web app, synthetic traffic, label noise, old).
- Do not write conclusions the data does not support. If the implementation differs from docs/paper.md, record the difference in docs/DECISIONS.md.
- Every reference in the paper must be verified to exist (open the URL/DOI). Mark unverified ones as unverified.
