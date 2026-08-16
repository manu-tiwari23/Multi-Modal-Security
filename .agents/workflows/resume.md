---
name: resume
description: Reconstruct project state at the start of a session and report back before doing any work.
---

Run this at the start of any session, especially one that begins right after a limit cut off the previous session.

Steps:
1. Read `/PROJECT_CONTEXT.md` — note current tech stack and any "Not yet integrated" items
2. Read `/TODO.md` — find the "Currently Working On" section and its resume notes
3. Read the last 5 entries in `/CHANGELOG.md`
4. Read `/DECISIONS.md` for any entries marked "Open"
5. Read `/BUGS.md` for open bugs in the module you're about to touch

Then, before writing or changing any code, report back in this format:

```
Last completed: <most recent CHANGELOG entry>
Currently working on: <TODO.md "Currently Working On" item, plus resume notes if any>
Open decisions blocking this work: <any relevant Open items from DECISIONS.md, or "none">
Open bugs in this area: <any relevant open BUGS.md entries, or "none">
Proposed next step: <what you're about to do>
```

Wait for confirmation (or a correction) before proceeding, unless the human has already told you to continue without stopping.
