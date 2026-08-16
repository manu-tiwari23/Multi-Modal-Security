---
name: phishing-detection-module
description: Use when implementing or modifying anything under src/phishing/ — email analysis, URL scanning, attachment analysis, or the explanation generator.
---

## Conventions

- Each detector (email analyzer, URL/attachment scanner) is a stateless scoring service: input in, `{score, explanation}` out. Keep them swappable — don't couple them to each other.
- The Explanation Generator must always accompany a score with the specific signals that fired (e.g. "sender domain registered 3 days ago", "urgency language detected") — never return a bare number.
- Attachment analysis is **static/metadata analysis only** unless you've explicitly set up an isolated sandbox for detonation — never execute or open untrusted attachments in the main application environment.
- Use test/synthetic phishing samples for development, not real captured phishing emails containing real victim data.

## Testing Approach

- Unit test: email header parser against known-good and known-phishing sample headers
- Unit test: URL scanner against a small labeled set of benign/malicious test URLs
- Integration test: full pipeline (email in → score + explanation out) against a labeled test set, track basic precision/recall so detection quality is measurable, not just "it runs"

## Gotchas

- Reputation lookups (VirusTotal/AbuseIPDB) are rate-limited — cache results (see `PROJECT_CONTEXT.md` for the threat-intel cache) rather than calling the API on every scan.
- Don't let a slow external reputation lookup block the whole analysis — timeout and degrade gracefully to local signals only if the external call is slow.
