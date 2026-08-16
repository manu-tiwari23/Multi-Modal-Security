---
name: soc-module
description: Use when implementing or modifying anything under src/soc/ — log ingestion, detection rules, correlation, risk scoring, or alerting.
---

## Conventions

- All ingested logs must be normalized into the common event schema (defined in `ARCHITECTURE.md` §5) before being published to the event bus. Never let a raw, unnormalized log format leak into OpenSearch.
- Detection rules live as data (e.g. Sigma-style YAML/JSON), not hardcoded if/else chains — this keeps rules addable without code changes.
- The correlation engine groups events by shared entity fields (`ip`, `user`, `host`, `hash`) within a configurable time window. Document the window value in `PROJECT_CONTEXT.md` once chosen.
- Risk scoring must be a documented, explainable formula (e.g. weighted sum of rule severity + asset criticality + threat intel match) — not a black-box model. Analysts need to see why a score is what it is.
- Alert Manager must deduplicate before publishing — the same underlying incident should not generate multiple dashboard alerts.

## Testing Approach

- Unit test: normalization function against sample raw logs (including malformed ones)
- Unit test: risk scoring formula against known input/output pairs
- Integration test: publish a synthetic event to the bus → confirm it lands in OpenSearch correctly normalized
- Integration test: publish two related synthetic events → confirm correlation engine groups them into one incident

## Gotchas

- Don't couple detection logic directly to the honeypot or phishing modules — they should just be additional event sources on the same bus, no special-casing.
- Watch for clock skew between event sources when correlating by time window.
