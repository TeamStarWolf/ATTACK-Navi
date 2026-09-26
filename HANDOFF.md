# HANDOFF — current state

Living coordination note. Keep it factual and current; update or delete stale items rather than piling on. Read `AGENTS.md` first.

_Last updated: 2026-09-26._

## Active initiative: make ATTACK-Navi the front-end for the whole library

Three-phase effort so the app opens on a repo-wide view and lets you traverse everything the TeamStarWolf library holds, ATT&CK-centered.

- **Phase 1 — new default layer. ✅ MERGED (PR #57).** The matrix now defaults to the `unified` composite ("Unified Coverage") instead of mitigation-only `coverage`, recolored to an ATT&CK-brand navy → sky → violet ramp. `?heat=coverage` links still work; `coverage` stays in the menu.
- **Phase 2 — named library layers. 🚧 IN PROGRESS (Claude Code).** Adding selectable layers sourced from the library: Web Application Attacks, CWE weakness-classes, CAPEC families, and per-domain sets (cloud, Active Directory, ransomware TTPs, container/K8s, OWASP Top 10). **If you are Codex: do not edit the heatmap-mode / layer files right now** (`models/heatmap-modes.ts`, `services/filter.service.ts`, `components/matrix/*`, `components/technique-cell/*`, `components/legend/*`) to avoid collision — pick other work or ask.
- **Phase 3 — full relationship traversal. ⏳ NOT STARTED.** Extend `components/technique-graph-panel` so any node re-centers, and add control / D3FEND / CVE / CWE / CAPEC edges (CTID-Mappings-Explorer style). Needs new reverse indexes for controls/CVE/CWE/CAPEC/D3FEND in `Domain`.

## Repo state

- `main` is current; Phase 1 (#57) merged. Remote: `github.com/TeamStarWolf/ATTACK-Navi` (uses PRs; CI = CodeQL, Docker smoke build, dependency-review, Snyk).
- Unit suite: **710 tests, green.** Keep it that way.

## How to pick up work

1. `git status --short`, then `npm install` if needed.
2. `npm start` to run the dev server; verify with `npx tsc --noEmit -p tsconfig.app.json` and `npx ng test --watch=false --browsers=ChromeHeadless`.
3. Follow `AGENTS.md` for conventions and the "adding a heatmap mode" checklist.
4. Branch, implement, test, and only open a PR if the user asks.

## Notes for the next agent

- Data source of truth for the new layers is the TeamStarWolf library repo (`data/`, `navigator/`, and the discipline/reference docs). Layers should be authored in the MITRE Navigator layer JSON format the app already imports (`services/navigator-layer.service.ts`).
- Respect ATT&CK version skew (`Domain.supersededBy`) when mapping library data (often pinned to older ATT&CK) onto the live matrix.
