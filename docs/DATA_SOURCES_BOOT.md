<!-- ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
     https://github.com/TeamStarWolf/ATTACK-Navi - MIT License -->
# External data sources on boot — inventory

The Phase-3 pinning inventory: every external URL the app requests on a cold load,
which service issues it, and when. Built from the code (`src/app/services/*.ts`, with
`src/app/services/source-inventory.ts` the canonical `SOURCE_DEFINITIONS` registry) and
from a network capture of the production build.

## Headline: the default boot fetches 33 files from GitHub before any action

On a cold load of `#/` → `#/matrix`, with no user action, the app issues **33 GitHub
requests — 27 `raw.githubusercontent.com` + 6 unauthenticated `api.github.com`** — plus
`d3fend.mitre.org/api/technique/all.json` and 3 Google Fonts. The data-source **mode
does not change this**: the live-ATT&CK, cross-framework, enrichment and detection
layers load on boot regardless; only `enterprise-attack.json` differs (fetched live, or
served from the IndexedDB cache). The toolbar shows `v19.2` (bundled) at ~2.5 s and
flips to `v20.0` after the live STIX arrives (~15 s); the first GitHub request fires
~1.8 s after load.

> **Changed since this capture (rule-coverage snapshot, 2026-10-21):** the Elastic
> detection-rules, Splunk security_content and mdecrevoisier SIGMA-detection-rules tree
> listings are no longer requested. Their rule coverage is read at build time from the rule
> bodies at pinned commits (`scripts/build-rule-coverage-snapshot.mjs`) and shipped as
> `src/assets/data/rule-coverage-snapshot.json`, fetched from the app's own origin. A cold
> load should therefore make **3** unauthenticated `api.github.com` calls (the two KEV
> `contents` calls and `trickest/cve`), not 6. The counts in this document are from the
> earlier capture and have not been re-measured; `docs/MEASUREMENTS.md` will show the change
> at its next `node scripts/measure.mjs` run.

### Measured (production build, Chrome headless, fresh profile, `networkidle` + 20 s)

| Mode | Phase | raw.githubusercontent | api.github.com | other external |
|---|---|---|---|---|
| default (live), fresh | boot `#/` → `#/matrix` | 27 | 6 | d3fend 1, gstatic 3 |
| default | each of 10 routes | 0 | 0 | 0 |
| bundled (toggled after boot) | boot | 27 | 6 | same |
| bundled | toggle + 10 routes | 0 | 0 | 0 |
| live (bundled → live) | boot | 27 | 5 † | same |
| live | toggle + routes | 0 (enterprise from IndexedDB cache) | 0 | 0 |
| revisit (same profile, 2 loads) | boot ×2 | 49 | 10 ‡ | d3fend 2, www.cisa.gov 1, gstatic 4 |
| revisit | `#/exposure` | 1 (cisagov kev-data — KEV retry, see below) | 0 | 0 |

**†** The `5` (vs 6) is an **environmental artefact, not a mode effect**: `live.json` is missing
the second `contents` call (`kev/attack-16.1`) yet still fetched the `kev-07.28.2025` raw file,
because `resolveKevUrl()` fell to its `catchError(() => of(pinned))` (`attack-cve.service.ts:128`)
when that `contents` call failed — almost certainly the 60 req/hr unauthenticated limit after the
earlier capture runs from the same IP.

**‡** The two revisit loads are **not symmetric**: `capture.cjs` reloads as soon as the `load`
event fires, so the first revisit load is cut short (4 api) and the full one makes 6 — do **not**
halve the ×2 totals.

The mode toggle and route navigation add **no** GitHub traffic; everything is the boot burst.
The IndexedDB cache drops only `enterprise-attack.json` (a raw file), **never an api call**, so a
primed revisit still spends **6** unauthenticated api calls, the same as a cold load.

## Boot inventory — exact URLs

### `api.github.com` — unauthenticated, rate-limited (Phase-3 priority)

6 anonymous REST calls per cold load share the **60 req/hr/IP** limit — the surface most
worth pinning (replace with a build-time tree snapshot or a pinned release asset). As of the
rule-coverage snapshot, the three rows marked *removed* are no longer requested (see the note
above), leaving 3.

| Endpoint | Issuing service |
|---|---|
| `/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/kev` | `attack-cve.service.ts` |
| `/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/kev/attack-16.1` | `attack-cve.service.ts` (runtime-derived second call) |
| `/repos/elastic/detection-rules/git/trees/main?recursive=1` | `elastic.service.ts` (*removed*: bundled `rule-coverage-snapshot.json`) |
| `/repos/mdecrevoisier/SIGMA-detection-rules/git/trees/main?recursive=1` | `sigma.service.ts` (*removed*: bundled `rule-coverage-snapshot.json`) |
| `/repos/splunk/security_content/git/trees/develop?recursive=1` | `splunk-content.service.ts` (*removed*: bundled `rule-coverage-snapshot.json`) |
| `/repos/trickest/cve/git/trees/main?recursive=1` | `poc-exploit.service.ts` |

### `raw.githubusercontent.com` — 27 blobs on boot (26 distinct; Sigma coverage fetched twice)

- **Live ATT&CK** — `mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` (the v20.0 STIX; cached on revisit)
- **CTID mappings-explorer** (`main`) — `nist_800_53`, `aws`, `azure`, `gcp`, `veris`, `cri_profile` (all `attack-16.1`), `csa_ccm` (`attack-17.1`), `m365` (`attack-16.1`), and the runtime-resolved `kev/attack-16.1/kev-07.28.2025/enterprise/…json`
- **ATT&CK→CVE** — `center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv`
- **CVE2CAPEC** (`Galeax/CVE2CAPEC/main/database`) — `CVE-2026.jsonl.gz` and `CVE-2025.jsonl.gz`
- **CISA KEV** — `cisagov/kev-data/develop/known_exploited_vulnerabilities.json`
- **CAPEC** — `mitre/cti/master/capec/2.1/stix-capec.json`
- **MITRE Engage** (`mitre/engage/main/Data/json`) — `activities.json`, `approach_activity_mappings.json`, `attack_mapping.json`, `goal_approach_mappings.json`, `goals.json`
- **CAR** — `mitre-attack/car/master/docs/car_attack/car_attack.json`
- **Atomic Red Team** — `redcanaryco/atomic-red-team/master/atomics/Indexes/Attack-Navigator-Layers/art-navigator-layer.json`
- **Sigma coverage** — `SigmaHQ/sigma/master/other/sigma_attack_nav_coverage.json` (fetched twice)
- **MISP galaxy** — `MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json`
- **ThreatHunter-Playbook** — `OTRF/ThreatHunter-Playbook/main/docs/hunts/windows/attack_navigator.json`
- **Anthropic skills layer** — `mukul975/Anthropic-Cybersecurity-Skills/main/mappings/attack-navigator-layer.json`

### Other external on boot
- `d3fend.mitre.org/api/technique/all.json` — D3FEND ontology (`d3fend.service.ts`)
- `fonts.gstatic.com` — 3 Google web-font files (IBM Plex Mono, Inter)
- `www.cisa.gov/.../known_exploited_vulnerabilities.json` — CISA KEV feed (non-GitHub), the
  boot-phase **fallback** for the GitHub KEV mirror (see below); it appears on boot only when
  that mirror failed or timed out.

### KEV fallback / retry (a failure path, not route or revisit behaviour)
`cve.service.ts` loads KEV once on boot, and `loadKev()` is a no-op afterwards (`cve.service.ts:108`).
It first tries the raw GitHub mirror `cisagov/kev-data/develop/known_exploited_vulnerabilities.json`
with `timeout(10000)` and, on failure, `catchError` falls back to the `www.cisa.gov` feed
(`cve.service.ts:113-115`). So the two KEV refetches in the capture are that failure path, not
normal navigation:
- the `cisagov/kev-data` request at `#/exposure` in the revisit run is a **retry** that fires only
  because the boot KEV load had failed — in `default.json`, `#/exposure` makes **0** external requests;
- the `www.cisa.gov` hit is the same fallback, during **boot**.

## Mode is not persisted

`DataService.mode` is `'live'` at `data.service.ts:102` with **no storage key**, so the
choice resets to live every load and cannot be preset — the capture toggled it in the
toolbar after boot. **E1.4 (defaulting to bundled) will not, on its own, make boot
clean**: the live-ATT&CK, CTID, enrichment and detection layers fetch on boot in both
modes. Making cold boot quiet is Phase-3 pinning work, not a mode default.

## Phase-3 pinning notes

1. **Prioritise the 6 `api.github.com` endpoints** — unauthenticated, 60 req/hr shared;
   a cold load spends 6, and a primed revisit spends 6 as well (the IndexedDB cache drops
   only the raw `enterprise-attack.json`, never an api call). Pin to a build-time tree
   snapshot or release asset. Done for Elastic, Splunk and mdecrevoisier SIGMA (the bundled
   rule-coverage snapshot, pinned per commit and refreshed monthly by `refresh-data.yml`).
2. **Pin the floating refs.** Every live source tracks a moving branch
   (`master`/`main`/`develop`), so content can shift under the app — record the exact
   commit/ref at build time (mirrors the bundled `BUNDLED_ATTACK_VERSION` discipline in
   `source-inventory.ts`).
3. **Bundle or proxy the boot burst.** 33 GitHub blobs + the D3FEND ontology load before
   the user does anything; bundling them (as ATT&CK/CWE/F3/SSVC already are) or routing
   them through a pinned mirror removes the cold-boot rate-limit and availability risk.
