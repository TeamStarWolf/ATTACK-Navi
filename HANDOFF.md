# HANDOFF — current state

Living coordination note. Keep it factual and current; update or delete stale items rather than piling on. Read `AGENTS.md` first.

_Last updated: 2026-09-26._

## Active initiative: make ATTACK-Navi the front-end for the whole library

Three-phase effort so the app opens on a repo-wide view and lets you traverse everything the TeamStarWolf library holds, ATT&CK-centered.

- **Phase 1 — new default layer. ✅ MERGED (PR #57).** The matrix now defaults to the `unified` composite ("Unified Coverage") instead of mitigation-only `coverage`, recolored to an ATT&CK-brand navy → sky → violet ramp. `?heat=coverage` links still work; `coverage` stays in the menu.
- **Phase 2 — named library layers. ✅ MERGED (PR #59).** A `library` heatmap mode + "📚 Library Layers" picker colors the matrix by 8 curated layers (Web Application Attacks, CWE weakness-classes, CAPEC families, cloud, Active Directory, ransomware TTPs, container/K8s, OWASP Top 10), authored by Codex in the library repo and vendored to `src/assets/data/library-layers/`. `LibraryLayerService` loads the manifest + per-layer scores; navy→sky→violet ramp.
- **Phase 3 — full relationship traversal. 🚧 IN PROGRESS (Claude Code).** Extend `components/technique-graph-panel` so any node re-centers, and add control / D3FEND / CVE / CWE / CAPEC edges (CTID-Mappings-Explorer style). Needs new reverse indexes for controls/CVE/CWE/CAPEC/D3FEND in `Domain`. **Codex: stay off `components/technique-graph-panel/*` and `models/domain.ts` while this is active.**
- **HTB Technique Frequency layer — ⏳ QUEUED (Claude Code).** Analyze the HackTheBox writeups (Google Drive; Claude-only access) to score techniques by real-world practice frequency; hand Codex the aggregated counts to format as a 9th library layer.

## Claude/Codex coordination

- Chris designated Claude Code as the authoritative AI coordinator for this repo.
- Codex should use this handoff to understand Claude's current work, then wait for a Claude/user assignment before taking implementation work.
- Codex can help Claude by preparing repo-state summaries, checking status, running verification, reviewing tests, or taking non-overlapping tasks Claude explicitly leaves open.
- Until Claude or Chris redirects, Codex should not edit the Phase 2/Phase 3 active files named above.

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
