# ATT&CK-Navi — Harsh Product Critique

**Reviewer:** @WolfenLabs · **Date:** 2026-11-16 · **Target:** live app at `teamstarwolf.github.io/ATTACK-Navi/` (ATT&CK v19.2 bundle)
**Method:** drove the live app — walked all 9 rail workspaces and their ~60 sub-views, switched heat lenses, opened technique dossiers, ran the mobile layout, and read the network/console tape. This is a product critique, not an engineering review. The brief was "be bitter and objective about features that just suck," so the praise is deliberately rationed and the knives are out. Where the app is genuinely good, it says so once and moves on.

**One-line honest baseline:** this is *not* vaporware. The grounded data is real — CISA KEV (1,781 entries), SigmaHQ rule counts, Atomic Red Team, D3FEND, CTID control mappings (NIST/CRI/CIS/CSA CCM), group prevalence, CVE/EPSS. It objectively aggregates more than the official MITRE Navigator does. The problem is not emptiness. **The problem is that it has no idea when to stop**, and it has quietly vandalized the one thing an ATT&CK tool is not allowed to touch: the ATT&CK taxonomy.

---

## A) What sucks (worst first)

### A1. It renamed the ATT&CK tactics. This is the single worst decision in the product.
The matrix does **not** show MITRE's 14 Enterprise tactics. It ships **15 columns** because it split *Defense Evasion* into two invented tactics: **"STEALTH" (30 techniques)** and **"DEFENSE IMPAIRMENT" (18)**. These names appear in the column headers, the dashboard tactic breakdown, the Detect table (`tactic: stealth`, `tactic: defense-impairment`), and the lens groupings — the custom scheme is baked through the whole app, not a cosmetic skin.

Why this is the top finding, not a nitpick:
- **An ATT&CK tool's entire reason to exist is fidelity to ATT&CK.** The taxonomy *is* the product's contract with its users. A SOC analyst, a detection engineer, a red-teamer, and a CTI vendor all speak "Defense Evasion." None of them speak "Defense Impairment." The first reaction of anyone who knows ATT&CK is "…where did Defense Evasion go, and who gave this tool permission to rewrite MITRE?"
- **It silently breaks mental interop.** Every other artifact in this person's world — MITRE Navigator, vendor coverage maps, DeTT&CT, CTI reports, the ATT&CK website — uses the canonical names. Navi is now the *only* surface that disagrees, which makes it the thing you distrust.
- **It's not even labeled as opinionated.** There's no "custom taxonomy" badge, no toggle back to canonical MITRE tactics, no footnote. It just presents a non-standard vocabulary as if it were ATT&CK.

Fix is non-negotiable: default to canonical MITRE tactic names. If the split is a genuinely useful analytic lens, make it an *opt-in* view with a loud "non-standard" label — never the default face of the tool.

### A2. The default view is a flat wall of "1"s that teaches the user nothing.
Land on the matrix and the default lens is **Frequency**. In Reconnaissance and Resource Development *every single technique and sub-technique shows "1"* (T1589.001 = 1, T1590.002 = 1, T1583.004 = 1 …). The heatmap is uniform. The first impression of a "36-lens threat workbench" is a column of identical badges that convey zero signal. The data only becomes differentiated deep in Initial Access/Execution. A product's cold-open should be its most convincing frame; this one is its least.

### A3. The default Dashboard flatters you with numbers that mean nothing about your defense.
`#/dashboard` leads with **"98% mapped," "100%" green bars** across most tactics (Reconnaissance 100% 12/12, Initial Access 100% 11/11, Discovery 97% 33/34…). A tired analyst reads a sea of green and feels covered. The actual meaning, buried in grey small-print, is: *"Known: mapped 217 of 222. No data of yours recorded. Known counts reference mapping only."* In other words the headline metric is **"does MITRE publish a mitigation for this technique"** — a near-tautological fact about ATT&CK itself, not about your environment. Shipping a 98%-green "Threat-Informed **Defense** Dashboard" that measures nothing about the user's defense is, at best, misleading framing and, at worst, a vanity dial. The honest default would show **0% / "no posture recorded yet — import your environment"** until the user tells Navi something real.

### A4. ~7.6 MB per page load, 5.8 MB of it one raw JSON file.
The matrix view pulls **116 requests / ~7.6 MB**. Of that, **6.7 MB is JSON across 34 files**, dominated by a single **5.8 MB raw `enterprise-attack.json`** STIX bundle shipped to the browser and parsed client-side, plus a 730 KB `library.json`. The JS is actually fine (51 chunks, ~785 KB). The sin is shoving the entire uncompressed ATT&CK STIX bundle at every visitor instead of pre-processing it into a slim, indexed, compressed payload. On a phone or a conference-center network this is a multi-second hit before anything is usable.

### A5. A flaky asset fetch throws an uncaught framework error instead of retrying quietly.
The console shows a transient `503` and an `ERR_FAILED` on lazy chunks (`chunk-Bzrchohn.js`, `chunk-C_3QJ0dR.js`) that **then succeed on retry (200)** — so nothing is permanently broken. But on the first failure the app surfaces an uncaught **Angular NG0750 deferred-load error**. The resilience works; the *error hygiene* doesn't. A hardened tool swallows a transient chunk miss and retries without ever bubbling a red framework stack trace.

---

## B) Half-baked or pointless — which of the 34 lenses / 10 workspaces are filler?

The advertised "36 lenses" is actually **34** (one, "F3 Origin," is permanently disabled as "n/a for Enterprise ATT&CK" and just sits there greyed out — cut it from the Enterprise picker entirely instead of showing a dead control). Beyond that, the lens picker also hangs **201 "library layers"** off the same menu. That's the real bloat story.

**Genuinely valuable lenses (keep, these are the product's actual moat):** KEV, CVE, EPSS, Sigma Rules, CAR, Atomic, D3FEND, Mitigations mapped, NIST 800-53, Frequency. These are differentiated, data-backed overlays you cannot get in one place in MITRE Navigator.

**Filler / vanity / nobody-will-touch:**
- **"Lylat Mission Coverage"** and **"Agentic AI Swarm Intrusion"** — persona/novelty layers masquerading as analytic lenses. A real SOC lead evaluating this tool sees "Lylat Mission Coverage" in a security product's lens menu and quietly closes the tab. Vanity cruft belongs in a demo build, not the shipped lens list.
- **8 separate "HTB" (Hack The Box) frequency layers** (`HTB Core 528`, `HTB Linux`, `HTB Windows`, `HTB Easy/Medium/Hard/Insane`…) — hyper-niche CTF-grind data elevated to the same tier as CISA KEV. One collapsed "HTB" group would do; eight top-level entries is hoarding.
- **"F3 Origin"** — a permanently-disabled Enterprise lens. Dead UI.
- **"Reference depth"** and **"Library Layer"** as distinct lenses blur into "how much reference data exists," which overlaps "Mitigations mapped" and "Detection content available." Several lenses measure the same underlying "we have data here" signal in slightly different clothes.

**Workspaces that are suspiciously thin or aspirational:**
- **Detection Validation / Purple Team** (inside Detect, and the "Detection Validation → Open Workbench" block in every technique dossier) renders **"UNTESTED — No validation runs recorded for T1078 yet."** It's a promise of a feature, not a feature. Every technique advertises a validation workbench that is empty by construction because there's no execution backend behind it.
- **Exposure** is a *ten-tab* mini-app on its own (CVE, Risk, Kill Chain, Graph, Gap Analysis, Priority, SSVC, Dossier, What-If, CTEM) — and the CVE tab alone has 7 more sub-tabs. "SSVC," "What-If," "CTEM," "Dossier" as separate top-level tabs smells like one feature fragmented into ten buzzword-named rooms. (KEV Dashboard inside here is excellent and does *not* deserve to be buried four clicks deep behind nine sibling tabs.)
- **Library** quietly became an "awesome-security-list": **1,329 assets including 203 X/Twitter accounts and 94 channels.** A catalog of 203 Twitter handles is scope creep that has nothing to do with being an ATT&CK workbench.

**Net:** the moat is ~10 data lenses and 3–4 workspaces (Matrix, Exposure/KEV, Intel, Detect). The other ~24 lenses, 201 library layers, and half the workspace tabs are a museum of everything the author could find a dataset for.

---

## C) UX friction

- **Decision paralysis by design.** Real surface area isn't "10 workspaces." It's **9 rail items × up to 10 tabs each × 5-step wizards × 34 lenses × 201 layers × 44 data-source filters × a "Viewpoint" persona switcher.** There is no opinionated "if you're a detection engineer, start here" path. The onboarding tour is good (3 steps + "Run Assessment / View Gaps / Browse Intel / Import Assets" quick-starts) — and then it dumps you into a cockpit with 300 switches and no autopilot.
- **The technique dossier is a ~48-section data-dump with no progressive disclosure.** Open T1078 and you get Sigma 118, Atomic 38, CAR, D3FEND 9, NIST 28, CRI 13, CAPEC 2, CVE 103, KEV 182, EPSS 21%, PoC 20, 47-group prevalence, six detection-source repos, an empty validation workbench, annotations… all expanded, all at once. There's a "Jump to section" index, which is itself an admission that the panel is too long to scroll. 90% of users want three things (what is it, who uses it, do I detect it); they have to quarry for them.
- **Inconsistent routing.** Bare `#/coverage` redirects to `#/dashboard/overview` instead of `#/coverage/assessment`; you only reach Coverage by clicking the rail item. Deep links to the obvious URL land on the wrong page.
- **"Defense Evasion" is unsearchable by name.** Because the tactic was renamed, a user scanning for the most important evasion tactic in ATT&CK won't find a column called that. (See A1.)
- **Mobile is a degraded reading mode, not a tool.** To its credit the layout *is* responsive — the rail collapses to a bottom nav and the 15-column grid reflows to a per-tactic vertical list. But the matrix's entire value (seeing the whole kill-chain at a glance, spatial heat) evaporates into an endless scroll, and a **desktop keyboard-hint bar ("↑↓ ←→ NAVIGATE · ENTER TO OPEN · / TO SEARCH") bleeds through and overlaps content** on the phone layout.

---

## D) What's missing

- **A canonical-MITRE mode.** The ability to say "show me real ATT&CK, standard tactic names" should exist and should be the default. Right now there is no escape from the custom taxonomy.
- **A real "your environment" on-ramp that isn't a cliff.** Every workspace honestly admits "reference only: not your deployed detections / no data of yours recorded." That honesty is good, but the entire product is theoretical until you feed it your stack — and the import path (layer JSON, "Import Assets") is heavyweight. There's no lightweight "paste your SIEM's enabled rule list" or "connect one source" that flips even one view from reference to real in 60 seconds.
- **Opinionated starting workflows / role presets** that pre-pick the lens, workspace, and filters for "detection engineer," "CTI analyst," "vuln manager." The "Viewpoint" switcher gestures at this but doesn't drive the whole surface.
- **Export parity with Navigator.** Navigator's lingua franca is the exportable/importable layer. Import-from-JSON exists; the critique didn't surface a confident, lossless *round-trip* export that a Navigator user could consume back — and with renamed tactics, any export is suspect until proven canonical.
- **Trust/provenance surfacing.** The data is real but its freshness is invisible. ATT&CK is "pinned 2026-08-05"; what about KEV, Sigma, EPSS? A visible "sources last refreshed" panel would convert "is this decorative?" skepticism into trust.
- **Honest empty/zero states on the dashboard** (see A3) that start at 0% posture.

---

## E) Concrete make-it-better moves (prioritized)

1. **Restore canonical MITRE tactic names as the default** (STEALTH/DEFENSE IMPAIRMENT → Defense Evasion). Make the split an opt-in, clearly-labeled "non-standard lens." *This is the credibility fix; do it before anything else.* (A1)
2. **Reframe the default Dashboard to measure posture, not reference coverage.** Start at 0%, label the green numbers honestly as "ATT&CK reference coverage," and gate the celebratory metrics behind real imported data. (A3)
3. **Pre-process and compress the ATT&CK bundle.** Replace the raw 5.8 MB `enterprise-attack.json` with a slim, indexed, gzipped/brotli payload or lazy-load per-tactic. Target sub-2 MB first paint. (A4)
4. **Pick a better default lens than Frequency**, or fix Frequency so Recon isn't a wall of "1"s. Lead with a lens that is visibly differentiated (e.g., KEV or Detection content). (A2)
5. **Cut the filler lenses.** Remove the disabled "F3 Origin" from the Enterprise picker; demote "Lylat"/"Agentic AI Swarm" to a hidden/demo group; collapse 8 HTB layers into one. Aim for ~12 curated lenses, not 34 + 201. (B)
6. **Add progressive disclosure to the technique dossier.** Default to a 3-section summary (What / Who uses it / Do I detect it), with everything else collapsed. The "Jump to section" index is a symptom — treat the disease. (C)
7. **Ship role-based starting workflows** that pre-configure workspace + lens + filters. Turn the "Viewpoint" switcher into a real driver. (C/D)
8. **Build a 60-second single-source on-ramp** so at least one view flips from reference to real without the full import ceremony. (D)
9. **Fix the small stuff:** silent retry on transient chunk fetches (kill the NG0750 surfacing); `#/coverage` → `/coverage/assessment`; remove the desktop keyboard-hint bar on mobile; move Twitter/channel catalogs out of the core ATT&CK Library. (A5/C/B)
10. **Surface source freshness** ("KEV updated X, Sigma updated Y") to prove the grounded data is live, not decorative. (D)

---

## F) Blunt one-paragraph verdict

ATT&CK-Navi is a genuinely impressive pile of real security data wearing a UI that mistakes "more" for "better." When it's good — the KEV dashboard, the Sigma/Atomic/D3FEND/CVE cross-referencing on a single technique, the honest "reference only" disclaimers — it does things MITRE Navigator simply can't, and for a solo analyst doing threat-informed-defense *research* it earns its existence as an exploration cockpit. But it drowns that moat in bloat: 34 lenses and 201 library layers and ten-tab workspaces and a catalog of 203 Twitter accounts, with no opinionated path through any of it, a dossier that data-dumps 48 sections at once, and a default dashboard that flatters you with 98%-green numbers that measure nothing you actually defend. And it commits the one unforgivable sin for an ATT&CK tool: it **renamed the tactics**, replacing "Defense Evasion" with invented "Stealth" and "Defense Impairment" columns and presenting its own vocabulary as if it were MITRE's — which torches interoperability and trust the moment an expert looks at it. Against the official Navigator it loses on fidelity, focus, speed, and shareability, and wins only on raw data breadth. Fix the taxonomy, start the dashboard at zero, delete half the lenses, and give users one clear path, and this becomes a tool people reach for instead of a tech demo they admire once and never open again.
