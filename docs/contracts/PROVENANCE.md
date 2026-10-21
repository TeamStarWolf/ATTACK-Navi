# Contract provenance

This folder holds ATTACK-Navi's own copies of the external contracts it consumes.
Each copy is a **structural pin**: a frozen, reviewable statement of the shape
Navi relies on, so a change on either side is caught by CI rather than in
production. A copy never carries live data; the data arrives at runtime, locally,
from the file a person imports.

<!-- truth-vocab-allow-next-line proven-only -- the schema filename; its rows are the range-Proven detections, each carrying its own date and source -->
## lylat-validated-detections.schema.json

| | |
|---|---|
| Contract | `lylat-validated-detections/1` |
| Pin status | **provisional** (`x-navi-pin: provisional`) |
| Producer head at pin | commit `9a50fb0` |
| Canonical projection | sha256: `eefe704a3838d98a94f19f9f58b82b90b89897b3bc2a29206c3a2b14aac56036` |
| Re-pin owner | P2-21 lifts the provisional pin once the producer tags a release of version 1 |

### What the pin covers

The schema is Navi's consumer copy of the producer's version-1 export schema as it
stood at producer commit `9a50fb0`. It is **provisional**: the producer has not yet
tagged a release of the schema, so the shape may still move. P2-21 removes the
`provisional` marker and re-pins the hash against the released schema. Until then,
Navi validates imports against this copy and refuses anything it does not describe.

Only the structure is pinned. The two prose/identity differences below are expected
and are **excluded from the hash** so they can differ without tripping CI:

- `$id` points at Navi's own location, not the producer's.
- `description` text is Navi's, written for Navi's reviewers; the producer's
  per-field prose and any `comment` / `$comment` annotations are not carried.

The pinned sha256 is computed by `scripts/check-lylat-contract.mjs` over a
**canonical projection** of the schema: every object's keys sorted, and the keys
`$id`, `description`, `comment` and `$comment` dropped at every level, serialised
as compact JSON. CI recomputes it on every run; a structural change to the schema
fails the check until the hash is re-pinned here in the same change.

### How a row maps into Navi (R6 §3)

An imported row is resolved and keyed **at import** through the same technique-ref
path a hand-entered run uses, so an imported run is indistinguishable from a manual
run of the same technique. The row's `coverage_state` and `outcome` decide the
run's status:

| Row | Run status |
|---|---|
| `negative_control` is `not-reproducible` | `not-reproducible` |
| `coverage_state` is `validated`, `outcome` is `alerted` or `blocked` | `passed` |
| `coverage_state` is `telemetry-observed` | `partial` |
| `coverage_state` is `detection-authored` or `deployed` | `untested` |

A row whose domain is `atlas`, or whose technique does not resolve in the loaded
domain, is dropped (with a reason) rather than imported. Every imported run is
range-scoped.

### Privacy rules

The export is designed to carry **no** host, path, account, address or rule body.
Navi enforces this on import, and CI enforces it on the fixtures, two ways:

1. **Structurally** — the schema sets `additionalProperties: false` at the top
   level, on each row and on `technique_ref`, so an unexpected key is refused; and
   every field is `enum`- or `pattern`-locked except the three free-id fields.
2. **By a privacy regex** over those three free-id fields — `mission_id`,
   `detection_ref` and `evidence_ref` — which refuses a path separator, an `@`, any
   whitespace, or a dotted-quad IP. One hit refuses the whole file; nothing is
   stored.

`detection_ref` carries a detection's `<source>:<id>` — the id only, never a query
or rule body. `evidence_ref` is an opaque run reference, never a URL. The negative
fixtures under `src/testing/fixtures/lylat/invalid/` exist to prove each of these
refusals keeps firing.
