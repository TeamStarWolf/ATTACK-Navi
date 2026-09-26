# AGENTS.md — Working in ATTACK-Navi

Canonical instructions for any AI coding agent (Codex, Claude Code, or other) working in this repository. `CLAUDE.md` points here. Read `HANDOFF.md` too — it holds the current in-flight state and who is working on what.

## What this is

ATTACK-Navi is a **browser-based MITRE ATT&CK analyst workbench** — an Angular single-page app, static (no backend), deployed to GitHub Pages. It renders the ATT&CK matrix and colors it by ~32 "heatmap modes" (coverage, detection, vulnerability, framework-mapping, threat-landscape lenses), with nine routed workspaces (Matrix, Dashboard, Intel, Detect, Exposure, Coverage, Library, Reports, Settings). It is the front-end companion to the **TeamStarWolf reference library** (`github.com/TeamStarWolf/TeamStarWolf`), whose datasets it consumes.

## Collaboration rules (all agents)

- Treat this as user-owned work. Preserve files, history, and intent. Keep edits scoped to the request.
- **Run `git status --short` before editing.** Never discard, reset, or overwrite changes you did not make unless the user asks. If a file changed under you, re-read it and work from the current version.
- Claude Code is the user's authoritative AI coordinator for this repository. Codex should follow Claude's task assignments, file ownership notes, handoffs, and sequencing instructions unless the user directly redirects or a safety/Git rule prevents the action.
- Codex and Claude Code follow the same rules and must avoid competing changes. **Check `HANDOFF.md` for what is in progress before touching those files.**
- Branch for meaningful work (`codex/` for Codex, `feat/`|`fix/`|`docs/` otherwise). Do **not** push, force-push, tag, or open PRs unless the user asks. Never commit secrets or machine state.
- Prefer the repo's existing structure and style. Add dependencies only when necessary.

## Stack & conventions (match these exactly)

- **Angular 21**, standalone components only (`standalone: true` with explicit `imports`), **hash routing** (`withHashLocation()`), `withComponentInputBinding()`.
- **`ChangeDetectionStrategy.OnPush` everywhere** — call `ChangeDetectorRef.markForCheck()` inside every subscription that updates view state.
- State services are `@Injectable({ providedIn: 'root' })` exposing `BehaviorSubject`-backed `xxx$` observables; consumers `combineLatest` and unsubscribe in `ngOnDestroy`.
- Templates use the new control flow: `@if` / `@for` / `@switch` (not `*ngIf`/`*ngFor`).
- **Icons:** every `<app-icon name="…">`, nav item, and route `data.icon` must be a key in `src/app/shared/icons/icon-registry.ts` (`ICONS`). Add the Lucide inner-SVG there first; only whitelisted SVG tags are allowed (a spec enforces this).
- **ATT&CK version skew:** the app renders **live** ATT&CK (currently v19.2) but many mapping datasets are pinned older (e.g. CTID at v16.1). `data.service.ts` parses `revoked-by` into `Domain.supersededBy` (retired id → current id). When you consume an older mapping dataset, translate ids through `supersededBy` — do not drop or mislabel retired ids.

## Build, run, verify

```bash
npm install
npm start            # ng serve — dev server (default :4200)
npx tsc --noEmit -p tsconfig.app.json          # fast typecheck
npx ng test --watch=false --browsers=ChromeHeadless   # unit suite (~710 tests, must stay green)
npm run build        # production build
npm run e2e          # Playwright e2e (in /e2e); test:visual for visual snapshots
```

Always run the typecheck and the unit suite after changes and report the result. A new mode/page/service ships with a co-located `*.spec.ts`.

## Where things live

- `src/app/models/heatmap-modes.ts` — the heatmap-mode list (dropdown source of truth).
- `src/app/services/filter.service.ts` — `HeatmapMode` union type + the **default mode** (`heatmapModeSubject`), URL (de)serialize.
- `src/app/components/matrix/` — the matrix; score builders (the big `else-if` chain), `getCellColor` minimap copy, 3× cell bindings in the HTML.
- `src/app/components/technique-cell/` — per-cell color (`ngOnChanges` per-mode `if/else`, `compute*Color` helpers).
- `src/app/components/legend/legend.component.ts` — `MODE_CONFIGS` (compile-enforced `Record<HeatmapMode, …>`).
- `src/app/services/*.service.ts` — one enrichment service per data source (D3FEND, Engage, NIST, CVE/KEV, EPSS, CWE, CAPEC, Sigma/CAR/Atomic, …); most lazy-load JSON from `src/assets/data/` or CTID/live URLs.
- `src/app/models/domain.ts` — the parsed `Domain` with all relationship maps + reverse maps + `supersededBy`.
- Routing: `app.routes.ts` + `app.routes-map.ts`; workspaces in `pages/<ws>/<ws>.routes.ts`; nav in `components/nav-rail`.
- Layer systems (separate from heatmap modes): `services/layers.service.ts` (workspace snapshots), `services/saved-views.service.ts`, `services/navigator-layer.service.ts` (MITRE Navigator layer JSON import/export).

### Adding a heatmap mode (touches ~6 places — all required)

1. `models/heatmap-modes.ts` (add to `HEATMAP_MODES`).
2. `services/filter.service.ts` (add to the `HeatmapMode` union).
3. `components/legend/legend.component.ts` (`MODE_CONFIGS` — compile-enforced).
4. `components/technique-cell/technique-cell.component.ts` (add the color branch in `ngOnChanges`).
5. `components/matrix/matrix.component.ts` (score builder in the mode `else-if` chain **and** the `getCellColor` minimap copy) + a `getXScore()` and `[input]` bound 3× in `matrix.component.html`.
6. A `*.spec.ts` update.

## Gotchas

- **CRLF:** this repo has `core.autocrlf` in play; a naive full-file read-modify-write can flip line endings and explode the diff. Prefer byte-safe edits and check `git diff --numstat` before committing.
- Do not break the unit suite. Do not introduce navy/glass legacy styles — the app is on a flat token design system.
- Keep colorblind-safe palettes (viridis / Okabe-Ito) working when you touch colors; there are CB branches alongside the default palettes.

## Reference docs in this repo

`ARCHITECTURE.md`, `CONTRIBUTING.md`, `WORKFLOWS.md`, `ROADMAP.md`, `DATA_SOURCE_SCORECARD.md`, `MAPPINGS_CHEAT_SHEET.md`, `OPEN_SOURCE_INTEGRATIONS.md`, `UPGRADE_FOUNDATION.md`.
