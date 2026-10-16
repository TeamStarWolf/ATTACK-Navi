# ATTACK-Navi Roadmap

This roadmap is the phase table of the **ATTACK-Navi Product Plan** dated 2026-10-13, written against main at `5831e2d`. The full plan (personas, the keep/consolidate/retire list, the data and architecture decisions, metrics, risks and owner decisions) is kept by the repository owner outside this repository; pull requests cite its epic ids, for example `E0.5`. It replaces the April 2026 roadmap that used to live here.

Counts quoted elsewhere in the docs (heatmap modes, routed workspaces and tabs, library layers, spec files, bundled ATT&CK versions) are generated from the code in [docs/FACTS.md](docs/FACTS.md) by `node scripts/gen-facts.mjs`, and `node scripts/check-facts.mjs` fails when README.md, ARCHITECTURE.md, HANDOFF.md or QUICKSTART.md disagree with them.

## Phases

| Phase | Weeks | Name | What the user notices at the end |
| :-- | :-- | :-- | :-- |
| P0 | 1-4 | Land the fixes, build the safety net | The product stops reporting KEV and NVD failure as success (#113): a failed KEV fetch is red and retryable instead of a silent 'loaded, 0'. ICS and Mobile are on 19.2 and F3 on 1.2, tactic names match everywhere, the data refresh fails loudly, and the hardening and licence notices are in. Every later change has a safety net and a measured cold and warm baseline. The SSVC 'exploitation unknown' rule follows in P1 and the dated KEV badge with the CVE page in P5. |
| P1 | 5-7 | Honest by default | The first screen no longer claims the organisation is covered, and no summary counts adversary interest as defense. Every lens says what it means, whose truth it is and how old it is; a failed feed is visible and retryable; invalid Sigma and Zeek output can no longer be exported; the matrix never changes version mid-session. |
| P2 | 8-10 | One posture model, visible on the matrix | Recording one validation run or marking one mitigation implemented visibly changes the default matrix, and a broad mitigation cannot paint dozens of cells Covered; every cell explains itself; the threat profile is chosen once and used everywhere; a technique link can be pasted into a ticket; the range lane has a fixed contract to build against. |
| P3 | 11-13 | Fast first load and pinned data | A cold first visit paints in about 2.5 s with no rate-limit zeros; Elastic, Splunk and Sentinel counts are honest; every source, hand-authored ones included, shows its version, licence and status on one page; Navi runs on ATT&CK v20.0 because the owner chose it, not because a background fetch swapped it. |
| P4 | 14-16 | Predictable navigation and a real first screen | 47 tabs become 27 in one move and every old link still works; a newcomer picks a role and lands on a Home that tells the truth; the technique drawer opens on the tab their role needs instead of a 35-section scroll; everything is reachable from the palette on a phone, a tablet or a 1280 px laptop. |
| P5 | 17-19 | CVE to decision to ticket, and back | The owner pastes CVE-2024-3400 on Home and in 4 clicks has the dated KEV badge, the SSVC decision with its inputs and SLA, the affected assets, the techniques, the owned controls that blunt them and a ticket packet on the clipboard. Closing the ticket (by hand or from a ticket export) feeds MTTM into the weekly brief. |
| P6 | 20-22 | Your stack, your rules, your proof, your progress | The owner declares the stack and drops a Splunk export: the matrix shows what is actually deployed, apart from what merely exists. The range's Kerberoast, AS-REP, noPac, group-edge and share/honeyfile detections appear as dated Proven-in-range cells. All layers live in one catalog, a newcomer can explore a watermarked sample org, and a learner can print a study page and export their progress. |
| P7 | 23-25 | Close the detection, hunt and CTI loops | A detection engineer goes from a ranked gap to a real SigmaHQ rule to a recorded validation in one workspace and can hand a hunter a dated hunt package; a CTI analyst turns a pasted report into a cited layer in under two minutes; the range receives a ranked 'prove these next' layer. |
| P8 | 26-28 | Matrix performance, accessibility and visual system | Lens switching feels instant; keyboard and screen-reader users can read the matrix with one tab stop; both themes are legible and colour-blind safe. |
| P9 | 29-31 | Reports, trend and every framework | A one-page executive PDF with honest, dated numbers and a quarter trend; ICS, Mobile, F3 and ATLAS show data or say n/a, never a silent zero, in the matrix and in every planner, playbook and query view. |
| P10 | 32-33 | Release operations, storage v2, retire and document | A smaller product (fewer components, routes and stylesheets, with no speed regression against P8), documented in one architecture doc that matches the code; the next ATT&CK release is a reviewed upgrade, not an accident. |

Total: 33 weeks, about 296 agent-days and 156 pull requests to review. Cut line: after Phase 7 (week 25). If review capacity shrinks, the work stops there; phases 8 to 10 can then stretch to one phase a month.

## Goals and epics by phase

### P0. Land the fixes, build the safety net (weeks 1-4)

Merge the 19 READY PRs in a fixed order and put characterization tests, journey skeletons and measurement in place before any redesign code. Four weeks because the owner reviews about 24 PRs in this phase.

- E0.1 Merge train for the 19 READY PRs
- E0.2 Characterization tests
- E0.3 Journey, redirect and accessibility skeletons
- E0.4 Measurement and sprawl baseline
- E0.5 One source of facts

### P1. Honest by default (weeks 5-7)

No screen calls reference availability coverage, no summary counts adversary interest as defense, every failure is visible, broken generated output stops shipping, and the version never changes under the user.

- E1.1 Truth vocabulary and CI lint
- E1.2 Lens metadata and definition cards
- E1.3 Truthful loaders, source records and SSVC
- E1.4 Pinned ATT&CK, vintage chip and Briefing strip
- E1.5 Honest first glance
- E1.6 Stop shipping broken or misleading output
- E1.7 One defensive reference count on the summary surfaces

### P2. One posture model, visible on the matrix (weeks 8-10)

Build PostureService and the shared threat profile before any navigation change, and make the owner's own truth visible on every lens.

- E2.1 PostureService (Known / Covered / Proven)
- E2.2 First registry lenses and overlays
- E2.3 Why-this-colour and technique deep links
- E2.4 Default-lens rule
- E2.5 Lylat contract v1, published early
- E2.6 ThreatProfileService and one picker

### P3. Fast first load and pinned data (weeks 11-13)

Move the public feeds to a pinned build step with a plan for every source, parse off the main thread, show provenance on one page, and adopt ATT&CK v20.0 on purpose.

- E3.1 Build-time data pipeline
- E3.2 Lazy loaders and lazy drawer
- E3.3 Pre-indexed ATT&CK and worker parse
- E3.4 Request hygiene: a replacement for every runtime tree
- E3.5 Library vendoring
- E3.6 Adopt ATT&CK v20.0 deliberately
- E3.7 Data & Trust page and source pages

### P4. Predictable navigation and a real first screen (weeks 14-16)

Move the whole IA once, with redirects, now that the posture model exists; give every visitor a meaningful first screen; split the technique drawer into role-ordered tabs; put personal state in one store.

- E4.1 IA move in one step
- E4.2 Home
- E4.3 Shell, palette and every viewport
- E4.4 Lens picker v2
- E4.5 Setup card, roles and the empty-state contract
- E4.6 Technique drawer in five role-ordered tabs
- E4.7 My items: one personal store

### P5. CVE to decision to ticket, and back (weeks 17-19)

Make the owner's primary flow effortless, including the close date that MTTM needs.

- E5.1 CVE page and peek
- E5.2 Exposure > Inbox
- E5.3 Findings importers
- E5.4 ReportService core, the ticket packet and the VM brief
- E5.5 Exposure > Plan
- E5.6 Close the loop: decisions, tickets and MTTM

### P6. Your stack, your rules, your proof, your progress (weeks 20-22)

Light Covered honestly from the owner's declarations and imports and Proven from the range; finish the layer store, the posture questionnaire, the sample org and the learner's study path.

- E6.1 Stack registry
- E6.2 Deployed-rule and production-alert importers
- E6.3 Detect > Coverage
- E6.4 Lylat proof live
- E6.5 Outcome ladder and contradicted state
- E6.6 One layer store
- E6.7 Rate your posture
- E6.8 Sample org 'Lylat Corp'
- E6.9 Learner study page and progress

### P7. Close the detection, hunt and CTI loops (weeks 23-25)

Gap to real rule to validation in one workspace, a hunt package from an actor, a layer from a report, and the range's work queue from Navi. Cut line: if capacity shrinks, stop here.

- E7.1 Content builder
- E7.2 Detect > Gaps
- E7.3 Threats consolidation
- E7.4 Proof wanted and loop back
- E7.5 One telemetry model
- E7.6 Report to layer
- E7.7 Hunt packages

### P8. Matrix performance, accessibility and visual system (weeks 26-28)

Finish the matrix strangler, make it usable by keyboard and screen reader, and burn down literal colours.

- E8.1 CellViewModel and last lens migrations
- E8.2 Matrix and dialog accessibility
- E8.3 Visual tokens
- E8.4 Blocking accessibility gate

### P9. Reports, trend and every framework (weeks 29-31)

Finish the report engine and the trend, retire the old summaries, and make ICS, Mobile, F3 and ATLAS first-class across every service, not only the matrix.

- E9.1 Remaining report templates
- E9.2 Snapshots and trend
- E9.3 Summaries consolidated
- E9.4 Domains, ATLAS and the cross-framework graph

### P10. Release operations, storage v2, retire and document (weeks 32-33)

Make the next ATT&CK release routine, finish storage, delete what was retired and document the result.

- E10.1 Release-upgrade flow
- E10.2 Storage v2
- E10.3 Retire
- E10.4 Docs and re-walkthrough

## How the work is delivered

- Agents author small PRs (<= 400 changed lines except data or generated files) from a fresh branch off synced main, list the changed files, attach screenshots and the measure.mjs delta; the owner reviews and merges (author is never merger).
- Every increment ends with a user-facing CHANGELOG entry and a re-measure.
- Owner review is the throughput limit. Phase lengths assume 6 reviews a week, the top of the 4-6 range, and every epic carries an estimated PR count, so no phase needs more than 6 reviews per week of its length (P0: 24 PRs in 4 weeks). At 4 reviews a week each phase stretches by about half, which is what the cut line is for.
- Pipeline work (lane B) can overlap UI work (lane A); characterization tests (lane C) always precede a rewrite of a surface. An epic that touches a file a pending PR changes waits for that PR, and the PR body names it.
- Cut line: after Phase 7 (week 25) the owner's two flows (with MTTM), Lylat proof, the detection, hunt and CTI loops and the learner path are done. Phases 8-10 can then stretch to one phase a month.
