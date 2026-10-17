# HANDOFF: current state

Living coordination note. Keep it factual and current; update or delete stale items rather than piling on. Read `AGENTS.md` first.

_Baseline verified: main at `8fbc6da` (one source of facts, #134), 2026-10-16 UTC._

## Phase 0 (2026-10-16)

The Phase 0 review train is merged: the 19 review PRs (#112-#128, #132, #133) and the safety nets, namely #134 (the facts pipeline, and ROADMAP.md rewritten from the plan), #135 (journey, redirect and accessibility e2e skeletons), #136 (characterization specs for the heatmap lenses, sidebar and dashboard KPIs), #137 (measurement harness and sprawl audit) and #139 (the refresh-data artifact is treated as untrusted and verified before the write-token job uses it). Counts and versions now have one source: `node scripts/gen-facts.mjs` writes [docs/FACTS.md](docs/FACTS.md) from the code, and `node scripts/check-facts.mjs` fails when README.md, ARCHITECTURE.md, this file or QUICKSTART.md disagree with it. Neither script runs in CI yet, so run both by hand before pushing a doc change. The phase plan and epic ids (`E0.1`-`E10.4`) are in [ROADMAP.md](ROADMAP.md).

## Active initiative: make ATTACK-Navi the front-end for the whole library

Three-phase effort so the app opens on a repo-wide view and lets you traverse everything the TeamStarWolf library holds, ATT&CK-centered.

- **Phase 1, new default layer. MERGED (PR #57).** Made the matrix default to the `unified` composite (now labelled 'Reference depth') in place of mitigation-only `coverage`, recolored to an ATT&CK-brand navy, sky and violet ramp. `?heat=coverage` and `?heat=unified` links still work and `coverage` stays in the menu.
- **Phase 2, named library layers. MERGED (PR #59, subsequently expanded).** The `library` heatmap mode lists 37 overlays from `src/assets/data/library-layers/index.json`. The original eight library-authored themes are only part of that inventory. See [docs/LIBRARY_LAYERS.md](docs/LIBRARY_LAYERS.md) for current counts and provenance.
- **Phase 3, graph enrichment. MERGED.** The technique graph has D3FEND and CAPEC nodes (`32ce99f`) alongside technique, subtechnique, parent, mitigation, group, software, CVE and campaign nodes. Clicking a technique, subtechnique or parent node selects that technique and rebuilds the graph around it; group, software, campaign and mitigation nodes re-center the graph (`04f05da`); Ctrl/Cmd-click on a group toggles it as a matrix filter and opens the Threat Groups panel; CVE, D3FEND and CAPEC nodes are inert leaves. Control and CWE node kinds are not implemented, so do not claim the broader original traversal design is complete.
- **HTB layer suite: MERGED (PRs #62, #69, #71, #73-75).** Eight views are present: broad frequency (535 machines), core (528), two OS subsets, and four difficulty subsets drawn from the separate 529-machine content cohort. Keep those cohorts separate from inventory distributions; no source documents or private source locations belong in the repository.
- **Toolchain: Angular 22 (PR #110, `ng serve` prebundling fix in #111), all four architect targets on `@angular/build` (#124).** Angular is 22.2.x with TypeScript 6.0.x (exact versions in `package-lock.json` and [docs/FACTS.md](docs/FACTS.md)); CI and the Dockerfile run Node 24. Enterprise ATT&CK is bundled at 19.2 (#73), ICS and Mobile ATT&CK at 19.2 and the CTID F3 Fraud Framework at 1.2 (#117). Remaining integration limitations are documented in [DATA_SOURCE_SCORECARD.md](DATA_SOURCE_SCORECARD.md).

## Claude/Codex coordination

- The repository owner designated Claude Code as the authoritative AI coordinator for this repo.
- Codex should use this handoff to understand Claude's current work, then wait for a Claude/user assignment before taking implementation work.
- Codex can help Claude by preparing repo-state summaries, checking status, running verification, reviewing tests, or taking non-overlapping tasks Claude explicitly leaves open.
- The orchestrator coordinates architecture, cross-repository review, registry decisions, and CI permissions. The library-builder lane owns companion-library MITRE content. Check the current assigned task before editing graph/model/data files; a stale historical handoff is not a new ownership claim.
- Agents author pull requests and the owner reviews and merges them; the author is never the merger (see "How the work is delivered" in [ROADMAP.md](ROADMAP.md)).
- The canonical task board is moving to GitHub Issues in the private training repository. This file records public-safe repository state only; private coordination transcripts and source locators must never be copied here.

## Repo state

- Verified main: `8fbc6da`, with 33 heatmap modes and 37 library layers (count per `src/assets/data/library-layers/index.json`), on Angular 22.2 / TypeScript 6.0. Remote: `github.com/TeamStarWolf/ATTACK-Navi`. Recheck live branch state before acting.
- Unit suite: Karma printed **Executed 1167 of 1167 SUCCESS** at `8fbc6da` (`npx ng test --watch=false --browsers=ChromeHeadless`). Quote the count Karma prints for the commit you verify rather than this number. `ci.yml` runs the archive-verifier tests, curated-layer validation, the unit suite and a production build, with no path filter, on pull requests and merge-group runs targeting main, on pushes to main, and on workflow_dispatch.
- Proxy suite: `npm test --prefix server` reported **24 tests, 24 pass, 0 fail** at `8fbc6da`.
- Playwright: `.github/workflows/e2e.yml` runs on pushes to main and on pull requests to main, both filtered to changes under `src/`, `public/`, `e2e/`, `playwright.config.ts`, `package.json`, `package-lock.json`, `angular.json`, `tsconfig*.json` or the workflow itself, and on `workflow_dispatch`. It is non-blocking (the deploy gates on unit tests and build only). The last run on main is push run 38964728109 on `1ee7ca2` (#121): success, 217 tests, 154 passed, 63 skipped (the `test.fixme` journey/redirect skeletons and the visual tests that skip in CI), and the flaky check found none. `8fbc6da` changed only docs and scripts, so the path filter did not run e2e on it.
- OSV: `.github/workflows/osv-scanner.yml` pins both jobs to osv-scanner-action v2.6.0 and passes only `-r ./` (the removed `--skip-git` flag is gone, #112). The scan executes and reports: push run 38965224153 on `8fbc6da` succeeded, scanning 656 packages in `package-lock.json` and 72 in `server/package-lock.json`, filtering 1 accepted advisory listed in `osv-scanner.toml` (with an expiry), and reporting no issues. The PR job scans both the base and the head and fails if either scan does not complete.

## How to pick up work

1. Read `AGENTS.md`, check current branch/remotes and `git status --short`, then use `npm ci` for the committed lockfile if needed.
2. `npm start` to run the dev server; verify with `npx tsc --noEmit -p tsconfig.app.json` and `npx ng test --watch=false --browsers=ChromeHeadless`.
3. Follow `AGENTS.md` for conventions and the "adding a heatmap mode" checklist.
4. Before pushing a doc change, run `node scripts/gen-facts.mjs --check`, `node scripts/check-facts.mjs` and `node --test scripts/check-facts.test.mjs`.
5. Branch from synced main, implement, test, and only open a PR if the user asks.

## Notes for the next agent

- The approved architecture makes the TeamStarWolf library (`data/`, `navigator/`) canonical for all layers. Library vendoring (E3.5, ROADMAP P3) and one layer store with all layers in one catalog (E6.6, ROADMAP P6) are still planned in [ROADMAP.md](ROADMAP.md); neither is deployed. Keep generators with their outputs and validate the workbench manifest after ingestion.
- Respect ATT&CK version skew (`Domain.supersededBy`) when mapping library data (often pinned to older ATT&CK) onto the live matrix.
- The repository keeps no social-preview image. Set one from a fresh capture in the repository's Settings > Social preview; the previous copy advertised an old Angular version and mode count. (Moved here from the README so the maintainer step is not in user-facing docs.)
