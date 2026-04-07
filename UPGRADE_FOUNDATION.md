# Upgrade Foundation

This repo now has enough UI surface area that a large redesign should be treated as a system upgrade instead of isolated component edits.

## What Was Added

- Global design tokens in [src/styles.scss](src/styles.scss)
- Reusable upgrade primitives in [src/styles/_upgrade-foundation.scss](src/styles/_upgrade-foundation.scss)
- Relaxed Angular build budgets in [angular.json](angular.json) so larger visual work can land incrementally

## Shared Primitives

Use these classes before introducing one-off visual patterns:

- `.surface-card`
- `.surface-panel`
- `.section-eyebrow`
- `.metric-value`
- `.pill-control`
- `.app-input`
- `.glass-toolbar`
- `.subtle-grid-overlay`
- `.accent-ring`
- `.warm-accent-ring`

## Recommended Upgrade Order

1. Shell and navigation
2. Matrix and sidebar
3. Shared overlay panels
4. Data-dense panels like timeline, scenario, risk, and detection
5. Component cleanup to reduce per-component SCSS size

## Guardrails

- Prefer CSS variables and shared utility classes over duplicating colors and panel chrome
- Keep ATT&CK data behavior separate from presentation changes
- When restyling a panel family, update the global/shared layer first
- Avoid adding more emoji-heavy copy in new UI work; treat current icons as legacy until replaced consistently

## Next Good Refactors

- Extract a shared panel shell component or shared SCSS partial for overlay drawers
- Extract shared chart/card primitives for dashboard, analytics, risk, and timeline panels
- Consolidate sidebar styles, which are currently the largest style hotspot
- Normalize typography and spacing scales across all panels
