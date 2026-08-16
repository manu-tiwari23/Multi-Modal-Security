---
name: honeypot-module
description: Use when implementing or modifying anything under src/honeypot/ — deceptive services, session recording, or attacker behavior analysis.
---

## Conventions

- Honeypot services must run in a network segment with no route to production systems, real credentials, or real user data — this is a hard rule, not a configurable option (see `AGENTS.md` guardrails). If a task seems to require connecting the honeypot to anything real, stop and flag it rather than doing it.
- All attacker interaction (commands typed, credentials attempted, files uploaded) gets recorded as a full session, then normalized into the common event schema and tagged `source: honeypot` before publishing to the event bus.
- Honeypot events should flow through the *same* pipeline as production SOC logs — don't build a separate storage path or dashboard for honeypot data; it should show up correlated alongside everything else.
- Behavior analysis (clustering sessions by TTP) is a separate downstream consumer of the event bus, not something computed inline during session recording.

## Testing Approach

- Manual test: connect to the deceptive service from an isolated test machine, confirm the session is fully captured
- Integration test: confirm a honeypot session event appears correctly normalized in OpenSearch and gets picked up by the SOC correlation engine
- Unit test: session parser against sample captured session logs

## Gotchas

- Don't log real credentials if you're testing with anything resembling production values — use obviously fake test credentials only, even in dev.
- Session recordings can get large; make sure they're capped/rotated so a long attacker session doesn't fill storage.
