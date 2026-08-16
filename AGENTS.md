# AGENTS.md — Rules for the AI Coding Agent

This file is read automatically at the start of every session. It is the source of truth for how to work on this project. If anything here conflicts with a one-off instruction in chat, ask before proceeding rather than silently picking one.

## Project

**Multi Modal Security (MMS)** — an integrated cybersecurity platform (SOC, AI Copilot, Honeypot, Phishing Detection, Digital Forensics, Threat Intelligence, Incident Response, ESP32 Physical Alerts, Dashboard). Full details: `ARCHITECTURE.md`, `REQUIREMENTS.md`, `PROJECT_CONTEXT.md`.

## Session Start Protocol

Before writing or changing any code, do the following, in order:
1. Read `PROJECT_CONTEXT.md` — current tech stack and environment state
2. Read `TODO.md` — find the "Currently Working On" item at the top
3. Read the last 5 entries of `CHANGELOG.md` — what was recently completed
4. Read `DECISIONS.md` — check if any past decision constrains the current task
5. Read `BUGS.md` — check if the feature you're about to touch has open bugs

Summarize what you found in one short paragraph before starting work, so the human can correct course early if your understanding is off.

## Build Rules

- **One feature at a time.** Do not start a second feature until the current one is implemented, tested, and logged. This project is built module-by-module, feature-by-feature — do not jump ahead to "make things faster."
- **No feature is done until it's tested.** After implementing a feature, write and run tests for it, then record the result in `TEST_REPORT.md` before marking it complete in `TODO.md`.
- **Update the paper trail every time**, not just at the end of a session:
  - `TODO.md` — check off the completed item, update "Currently Working On"
  - `CHANGELOG.md` — one entry per completed feature
  - `DECISIONS.md` — log any non-obvious technical choice you made and why
  - `BUGS.md` — log anything you found but didn't fix
- **Keep modules isolated.** Code for one module should not directly import internals of another module — communicate through the event bus / API layer as defined in `ARCHITECTURE.md`. If a task seems to require breaking this, stop and flag it as a decision rather than doing it silently.

## Session End Protocol

Before ending a session (or if you sense you're near a context/output limit):
1. Make sure `TODO.md`'s "Currently Working On" section accurately reflects the real state — including anything half-finished
2. Commit or clearly note any uncommitted/incomplete code so the next session doesn't lose it
3. Add a short "Resume notes" line to `TODO.md` if you stopped mid-feature (e.g. "stopped after writing the schema, still need the API endpoint and tests")

## Coding Standards

- Folder structure: `src/<module_name>/` for each module (e.g. `src/soc/`, `src/honeypot/`, `src/phishing/`, `src/forensics/`, `src/copilot/`, `src/alert-esp32/`), mirrored under `tests/<module_name>/`
- Each module exposes a clear interface (REST endpoint(s) and/or event bus topic(s)) — document new endpoints/topics in `PROJECT_CONTEXT.md` as you add them
- Prefer explicit, readable code over cleverness — this is a security tool; auditability matters more than brevity
- All config/secrets via environment variables, never hardcoded — document new variables in `.env.example` and `PROJECT_CONTEXT.md`

## Security & Ethical Guardrails (project-specific)

- The honeypot must run isolated from any real credentials, real production data, or the live internet beyond what's needed for realism — never wire it to anything real
- Do not implement actual exploit code, live attack payloads, or malware — use simulated/mock attack data and synthetic phishing samples for testing detection logic
- The ESP32/Physical Alert module must never receive raw logs, evidence, or credentials — status/severity metadata only
- The Incident Response module's Action Executor must always require human approval before executing any containment action — never remove or bypass this approval step

## Testing Requirements

- Unit tests for detection logic, scoring functions, and parsers
- Integration tests for anything that crosses the event bus (e.g. honeypot event → correlation engine → alert)
- Log every test run (pass/fail, what was tested) in `TEST_REPORT.md`

## When Uncertain

If a requirement is ambiguous or a design choice isn't covered in `ARCHITECTURE.md`/`REQUIREMENTS.md`, make the most reasonable assumption, implement it, and log the assumption in `DECISIONS.md` — don't block on it, but don't hide it either.
