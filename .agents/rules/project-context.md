# Project Context (pointer file)

This project keeps its single source of truth for project context at the **repo root**: `/PROJECT_CONTEXT.md`.

This stub exists only so Antigravity's built-in `.agents/rules/` discovery has something to find. Do **not** duplicate content here — if you (the agent) are tempted to write tech-stack notes, environment variables, or status snapshots into this file, put them in the root `PROJECT_CONTEXT.md` instead, so there's only one place to keep in sync.

If you're running Antigravity's `repo-research` skill or similar auto-context tooling and it wants to write findings to this path, redirect that output to root `PROJECT_CONTEXT.md` instead, or merge it in manually afterward — don't let two competing context files drift apart.
