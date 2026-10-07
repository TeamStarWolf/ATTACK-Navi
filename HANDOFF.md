# HANDOFF — current state

Living coordination note. Keep it factual and current; update or delete stale items rather than piling on. Read `AGENTS.md` first.

_Baseline verified: main at `5831e2d` (STRIDE threat model commit), 2026-10-06 UTC._

## Active initiative: make ATTACK-Navi the front-end for the whole library

Three-phase effort so the app opens on a repo-wide view and lets you traverse everything the TeamStarWolf library holds, ATT&CK-centered.

- **Phase 1 — new default layer. ✅ MERGED (PR #57).** The matrix now defaults to the `unified` composite ("Unified Coverage") instead of mitigation-only `coverage`, recolored to an ATT&CK-brand navy → sky → violet ramp. `?heat=coverage` links still work; `coverage` stays in the menu.
- **Phase 2 - named library layers: MERGED (PR #59, subsequently expanded).** The `library` heatmap mode now lists 36 overlays from `src/assets/data/library-layers/index.json`. The original eight library-authored themes are only part of that inventory. See [docs/LIBRARY_LAYERS.md](docs/LIBRARY_LAYERS.md) for current counts and provenance.
- **Phase 3 - graph enrichment: MERGED.** Main includes D3FEND and CAPEC nodes (`8eedbed`) alongside technique, mitigation, group, software, CVE, and campaign relationships. Scope qualification: the current click handler selects technique/subtechnique/parent nodes and routes groups to threat views; it does not recenter every node type, and control/CWE node kinds are not implemented. Do not claim the broader original traversal design is complete.
- **HTB layer suite: MERGED (PRs #62, #69, #71, #73-75).** Eight views are present: broad frequency (535 machines), core (528), two OS subsets, and four difficulty subsets drawn from the separate 529-machine content cohort. Enterprise ATT&CK was upgraded to v19.2 in #73. Keep those cohorts separate from inventory distributions; no source documents or private source locations belong in the repository.
- **Dependency/integration documentation baseline: MERGED (PR #76), then superseded by the Angular 22 upgrade (PR #110, with the `ng serve` prebundling fix in #111).** Angular runtime/compiler/build/CLI are now locked at 22.2.x with TypeScript 6.0.x (exact versions in `package-lock.json`); CI and the Dockerfile run Node 24. Remaining integration limitations are documented in [DATA_SOURCE_SCORECARD.md](DATA_SOURCE_SCORECARD.md).

## Claude/Codex coordination

- The repository owner designated Claude Code as the authoritative AI coordinator for this repo.
- Codex should use this handoff to understand Claude's current work, then wait for a Claude/user assignment before taking implementation work.
- Codex can help Claude by preparing repo-state summaries, checking status, running verification, reviewing tests, or taking non-overlapping tasks Claude explicitly leaves open.
- The orchestrator coordinates architecture, cross-repository review, registry decisions, and CI permissions. The library-builder lane owns companion-library MITRE content. Check the current assigned task before editing graph/model/data files; a stale historical handoff is not a new ownership claim.
- The canonical task board is moving to GitHub Issues in the private training repository. This file records public-safe repository state only; private coordination transcripts and source locators must never be copied here.

## Repo state

- Verified main: `5831e2d`, with 33 heatmap modes and 36 library layers, on Angular 22.2 / TypeScript 6.0. Remote: `github.com/TeamStarWolf/ATTACK-Navi`. Recheck live branch state before acting.
- Unit suite: **843 tests passed** at the verified baseline (`npx ng test --watch=false --browsers=ChromeHeadless`). Quote the count Karma prints for the commit you verified rather than this number. The Playwright suite runs in its own non-blocking workflow and completed its first green run on Node 24 / Angular 22 on 2026-10-07 (workflow_dispatch run 37553849248 on main, 29 passed / 6 visual tests skipped by design); it has no pull_request trigger until PR-Q (#119) lands. The proxy suite (`npm test --prefix server`) reports its own count.
- OSV: `.github/workflows/osv-scanner.yml` now declares `actions: read`, so the permission problem recorded earlier is fixed. The scan itself still fails to execute because both jobs pass a `--skip-git` flag that osv-scanner v2 removed, and the PR job reports green with no results; the repair is a separate PR. Do not describe an unexecuted scanner as green.

## How to pick up work

1. Read `AGENTS.md`, check current branch/remotes and `git status --short`, then use `npm ci` for the committed lockfile if needed.
2. `npm start` to run the dev server; verify with `npx tsc --noEmit -p tsconfig.app.json` and `npx ng test --watch=false --browsers=ChromeHeadless`.
3. Follow `AGENTS.md` for conventions and the "adding a heatmap mode" checklist.
4. Branch, implement, test, and only open a PR if the user asks.

## Notes for the next agent

- The approved architecture makes the TeamStarWolf library (`data/`, `navigator/`) canonical for all layers. Migration of the 28 workbench-only overlays and a pinned-commit vendoring script are still planned at this baseline; do not describe them as already deployed. Keep generators with their outputs and validate the workbench manifest after ingestion.
- Respect ATT&CK version skew (`Domain.supersededBy`) when mapping library data (often pinned to older ATT&CK) onto the live matrix.
