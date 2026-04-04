# Open Source Integrations

## Goal

The app already has strong ATT&CK coverage, but the next major jump in usefulness should come from integrating open-source cyber tools and datasets that make the matrix more operational.

The guiding principle is:

- ATT&CK should stay the center of the product.
- External integrations should answer "why does this technique matter right now?" and "what can I do about it?"
- New data should improve prioritization, detection coverage, validation, and intel context, not just add more panels.

## Priority Order

Recommended implementation order:

1. Sigma
2. Atomic Red Team
3. CISA KEV + NVD
4. MISP
5. OpenCTI
6. Zeek / Suricata
7. YARA / YARA-X
8. Security Onion
9. D3FEND deepening

## Tier 1: Immediate High-Value Integrations

### Sigma

Why it matters:

- Gives the app a real open detection layer.
- Maps naturally to ATT&CK techniques.
- Lets the product answer "do we have published detection logic for this technique?"

What to add:

- Technique-to-Sigma rule count
- Detection coverage heatmap mode
- Sidebar section for linked Sigma rules
- Filter for "has Sigma coverage" vs "no Sigma coverage"
- Export of ATT&CK techniques with linked Sigma coverage

Best UI surfaces:

- matrix heatmap
- sidebar detection section
- analytics panel
- risk scoring

Implementation notes:

- Start with static ingestion of Sigma metadata and ATT&CK tags.
- Do not begin with backend rule execution; begin with coverage and discovery.

### Atomic Red Team

Why it matters:

- Adds validation and purple-team value.
- Turns techniques into testable workflows.
- Helps answer "can we exercise this technique in our environment?"

What to add:

- Technique-to-Atomic test count
- "validated / testable / not testable yet" signal
- Sidebar list of Atomic tests
- Quick filter for techniques with Atomic coverage
- Readiness score input using Atomic availability

Best UI surfaces:

- sidebar
- scenario panel
- dashboard
- detection and purple-team views

Implementation notes:

- Ingest ATT&CK IDs, test names, supported platforms, prerequisites, and references.
- Keep execution out of scope initially; first ship visibility and linkage.

### CISA KEV + NVD

Why it matters:

- Provides urgency, not just relevance.
- Helps distinguish generic ATT&CK coverage from active exploit pressure.
- Supports "what should we fix first?" workflows.

What to add:

- KEV-backed risk multiplier
- Technique exposure lists tied to known exploited vulnerabilities
- CVE enrichment panel upgrades
- "high priority because KEV-backed" badges
- Dashboard widgets for KEV-exposed uncovered techniques

Best UI surfaces:

- risk matrix
- analytics panel
- CVE panel
- sidebar exposure sections

Implementation notes:

- KEV should be treated as a priority input, not just another badge.
- NVD should provide broad metadata and severity context.

## Tier 2: Strong Threat Intel Context

### MISP

Why it matters:

- Strong open-source CTI platform with tagging, correlation, and ATT&CK-friendly modeling.
- Good fit for operational intel teams.
- Can bring real-world indicators, reports, and events into the ATT&CK view.

What to add:

- Techniques linked to MISP events and tags
- Threat actor and campaign enrichment
- IOC-backed technique evidence counts
- Filters for "techniques seen in current intel"
- Analyst context panel for recent event linkage

Best UI surfaces:

- actor panels
- campaign timeline
- sidebar
- watchlist

Implementation notes:

- Start with import/sync of ATT&CK-tagged events and attributes.
- Build around enrichment and prioritization, not raw IOC browsing.

### OpenCTI

Why it matters:

- Stronger graph-native threat intelligence relationships.
- Better if the app needs provenance, confidence, and STIX-native relationships.
- Excellent for actor, malware, campaign, and intrusion-set storytelling.

What to add:

- Rich relationship overlays from techniques to actors, malware, tools, and campaigns
- Confidence-aware intel badges
- Source attribution and last-seen timelines
- Better actor compare and scenario building

Best UI surfaces:

- actor profile panel
- actor compare
- campaign timeline
- technique graph

Implementation notes:

- MISP and OpenCTI overlap.
- If only one is implemented first, choose based on user workflow:
  - choose MISP for event-driven operational CTI
  - choose OpenCTI for richer relationship graphing

## Tier 3: Open Detection Telemetry

### Zeek

Why it matters:

- Strong open-source network telemetry source.
- Good for data-source-backed ATT&CK detection mapping.

What to add:

- Technique coverage linked to available network telemetry
- Detection evidence mapping by data source
- Sidebar guidance for Zeek-based observability

Best UI surfaces:

- datasource panel
- detection panel
- sidebar data components

### Suricata

Why it matters:

- Strong open IDS/NSM source.
- Complements Sigma by covering alerting and network signatures.

What to add:

- Suricata-backed technique coverage
- Rule-count overlays by ATT&CK technique
- Gap identification for network-visible techniques

Best UI surfaces:

- detection panel
- analytics panel
- matrix heatmap

### Security Onion

Why it matters:

- Useful as an integration target because it bundles multiple open tools and operational workflows.
- Good future target if the product needs to show "detections available in a real open-source stack."

What to add later:

- bundle-level coverage metrics
- prebuilt ATT&CK-aligned detection posture views

## Tier 4: Malware / Content Enrichment

### YARA / YARA-X

Why it matters:

- Adds malware-oriented coverage dimension.
- Useful for file-centric and payload-oriented technique detection stories.

What to add:

- YARA-linked technique coverage
- Sidebar file/payload detection references
- Detection source filter for file-based analytics

Best UI surfaces:

- sidebar
- detection panel
- analytics panel

## Tier 5: Defensive Guidance Expansion

### D3FEND Deepening

Why it matters:

- D3FEND is already present in the app, but it can become much more actionable.
- Helps answer "what category of defensive action should we pursue?"

What to add:

- Better normalization of ATT&CK to D3FEND mappings
- Stronger grouping by defense category
- "recommended next defense" summaries
- Use D3FEND as remediation guidance in risk and scenario workflows

Best UI surfaces:

- sidebar
- scenario panel
- controls and priority views

## Product Strategy

The strongest product direction is:

- ATT&CK for navigation
- Sigma, Zeek, Suricata, and YARA for detection coverage
- Atomic Red Team for validation
- KEV and NVD for urgency
- MISP or OpenCTI for real-world intel context
- D3FEND for defensive action planning

That combination turns the app from a mitigation browser into an operational ATT&CK workspace.

## Recommended Implementation Phases

### Phase 1: Detection and Validation

Build:

- Sigma ingestion
- Atomic Red Team ingestion
- KEV and NVD refresh pipeline

Ship:

- new matrix heatmap modes
- stronger sidebar detection/testing sections
- better risk prioritization

### Phase 2: Threat Intel Enrichment

Build:

- MISP or OpenCTI connector
- actor, campaign, and malware enrichment pipeline

Ship:

- stronger threat workflows
- better actor comparison
- better campaign timelines

### Phase 3: Telemetry-Aware Detection Coverage

Build:

- Zeek / Suricata mapping layer
- datasource-driven detection scoring

Ship:

- more realistic "detectable in our stack" coverage
- clearer data source gap analysis

### Phase 4: Defensive Planning

Build:

- deeper D3FEND normalization
- remediation recommendation logic

Ship:

- guided defensive next steps
- better planning and prioritization views

## Data Model Suggestions

To support these integrations well, add normalized internal concepts for:

- external content source
- coverage type
  - mitigation
  - detection
  - validation
  - intel
  - exposure
- evidence confidence
- evidence freshness
- source attribution
- technique-to-content relationship count

This will make it easier to add new providers without rewriting each panel.

## UI Suggestions

When these integrations land, prioritize these UX patterns:

- one consistent "coverage stack" per technique:
  - mitigation
  - detection
  - validation
  - intel
  - exposure
- avoid creating one new panel per source unless necessary
- prefer enriching existing matrix, sidebar, analytics, and actor workflows
- use provider-specific panels only when the workflow truly needs them

## Recommended Next Build

If only one integration wave is started next, build:

1. Sigma
2. Atomic Red Team
3. KEV + NVD

That trio gives the fastest jump in real-world usefulness with the least conceptual sprawl.
