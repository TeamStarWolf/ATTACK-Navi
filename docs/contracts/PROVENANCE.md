# Contract provenance

This folder holds ATTACK-Navi's own copies of the external contracts it consumes.
Each copy is a **structural pin**: a frozen, reviewable statement of the shape
Navi relies on, so a change on either side is caught by CI rather than in
production. A copy never carries live data; the data arrives at runtime, locally,
from the file a person imports.

## `lylat-validated-detections.schema.json`

| | |
|---|---|
| Contract | `lylat-validated-detections/1` |
| Pin status | **provisional** (`x-navi-pin: provisional`) |
| Producer head at pin | commit `9a50fb0` |
| Canonical projection | sha256: `4e90dcfa6f057753498c49c13a24589407fcfe131b3b68a59dc2f529bbbb9f43` |
| Re-pin trigger | P2-21 re-pins the hash — and removes the provisional marker — against the producer schema at the **merge commit** that lands version 1 on the producer's default branch |

### What the pin covers

The schema is Navi's consumer copy of the producer's version-1 export schema as it
stood at producer commit `9a50fb0`. It is **provisional**: the version-1 contract
has not yet merged on the producer side, so the shape may still move. P2-21 removes
the `provisional` marker and re-pins the hash against the producer schema at its
merge commit (not a tagged release — the contract is gated on a merge, not a tag).
Until then, Navi validates imports against this copy and refuses anything it does
not describe.

Only the structure is pinned. This copy mirrors the producer's shape — field names,
the required sets, every enum and pattern, the `date` / `date-time` formats, and the
`allOf` conditional that requires `range_build_ref` once rows are present — with the
following deliberate, reviewed divergences, all **excluded from the hash** so they
can differ without tripping CI:

- `$id` points at Navi's own location, not the producer's (the producer's `$id`
  would publish the producer's repository name, which appears nowhere in Navi).
- `x-navi-pin` marks this copy provisional; the producer schema has no such key.
- `description` text is Navi's, written for Navi's reviewers; the producer's
  per-field prose and any `comment` / `$comment` annotations are not carried (the
  producer's prose would publish its internal file layout).
- The producer leaves `generated_at` as `format: date-time` only; this copy does
  the same (an earlier Navi draft added a redundant regex `pattern`, now removed).
- `row` and `technique_ref` are inlined, as the producer inlines them — no
  `definitions` / `$ref` indirection.

The pinned sha256 is computed by `scripts/check-lylat-contract.mjs` over a
**canonical projection** of the schema: every object's keys sorted, and the keys
`$id`, `description`, `comment` and `$comment` dropped at every level, serialised
as compact JSON. CI recomputes it on every run; a structural change to the schema
fails the check until the hash is re-pinned here in the same change.

### How a row maps into Navi (R6 §3)

An imported row is resolved and keyed **at import** through the same technique-ref
path a hand-entered run uses, so an imported run is indistinguishable from a manual
run of the same technique. Every field maps as follows:

| Contract field | Navi target | Notes |
|---|---|---|
| `technique_ref.id` | `run.techniqueId` (resolved) | a retired id remaps through the id resolver, exactly as a manual id does |
| `technique_ref.domain` | import gate only | `atlas` has no ATT&CK domain in Navi today, so those rows are dropped |
| `technique_ref.attack_version` | `outcomes[].sourceAttackVersion` (provenance) | the run is **keyed** with the loaded bundle's domain and version, never this value |
| `detection_ref` | `detectionsExpected`, `detectionsFired` (when `outcome` is `alerted`/`blocked`), `outcomes[].detectionRef` | the `<source>:<id>` identifier only |
| `coverage_state` + `outcome` | `run.status` (table below), `outcomes[].coverageState`, `outcomes[].outcome` | status is **set** from the row, never recomputed |
| `negative_control` | `outcomes[].negativeControl` | `not-reproducible` maps to the `not-reproducible` status |
| `validated_at` | `run.runDate` (date-only) | the date the range recorded for the run |
| `evidence_ref` | `outcomes[].evidenceRef` | opaque; never a URL (`evidenceLinks` stays URLs) |
| `mission_id` | `run.missionId`, and the run source `lylat-range:<mission_id>` | one source per mission; re-importing replaces that source |
| `range_build_ref` | — | export-level provenance; not stored per run |
| `generated_at` | `run.createdAt` / `run.updatedAt` | when the export was produced |
| `schema` | import discriminator | the file is refused unless the const matches |

The row's `coverage_state` and `outcome` decide the run's status:

| Row | Run status |
|---|---|
| `negative_control` is `not-reproducible` | `not-reproducible` |
| `coverage_state` is `validated`, `outcome` is `alerted` or `blocked` | `passed` |
| `coverage_state` is `telemetry-observed` | `partial` |
| `coverage_state` is `detection-authored` or `deployed` | `untested` |

A row whose domain is `atlas`, whose technique does not resolve, or whose resolved
technique is not one of the loaded domain's, is dropped (with a reason) rather than
imported. Every imported run is range-scoped.

### Privacy rules

The export is designed to carry **no** host, path, account, address or rule body.
Navi enforces this on import, and CI enforces it on the fixtures, two ways:

1. **Structurally** — the schema sets `additionalProperties: false` at the top
   level, on each row and on `technique_ref`, so an unexpected key is refused; and
   every field is `enum`- or `pattern`-locked. The three free-id fields
   (`mission_id`, `detection_ref`, `evidence_ref`) are pattern-locked too, but
   their patterns still admit characters that could encode a host, path, account
   or address, so they get a second check.
2. **By a privacy regex** over exactly those three free-id fields, which refuses a
   path separator, an `@`, any whitespace, or a dotted-quad IP. One hit refuses the
   whole file; nothing is stored.

`detection_ref` carries a detection's `<source>:<id>` — the id only, never a query
or rule body. `evidence_ref` is an opaque run reference, never a URL. The negative
fixtures under `src/testing/fixtures/lylat/invalid/` exist to prove each of these
refusals keeps firing.
