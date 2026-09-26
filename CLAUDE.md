# CLAUDE.md

This repository uses **`AGENTS.md`** as the shared instruction source for every AI coding agent (Claude Code and Codex alike).

**Before making any change:** read and follow `AGENTS.md`, then read `HANDOFF.md` for the current in-flight state and to avoid colliding with work another agent has in progress.

Quick reminders (full detail in `AGENTS.md`): Angular 21 standalone + OnPush, hash routing; icons must be registered in `shared/icons/icon-registry.ts`; adding a heatmap mode touches ~6 files; translate retired ATT&CK ids via `Domain.supersededBy`; run `npx tsc --noEmit -p tsconfig.app.json` and `npx ng test --watch=false --browsers=ChromeHeadless` after changes; `git status --short` before editing and never overwrite work you didn't make.
