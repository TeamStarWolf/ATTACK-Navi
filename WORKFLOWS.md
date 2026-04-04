# Workflows

## Goal

This app should not feel like a loose collection of cyber datasets. It should feel like one operational workflow built around ATT&CK.

The cleanest model is:

1. `Behavior`
2. `Intel`
3. `Exposure`
4. `Detection`
5. `Validation`
6. `Defense`

Each data source should strengthen one or more of those steps.

## Core Workflow

The main product loop should be:

1. start from an `ATT&CK` technique, tactic, actor, software, or campaign
2. enrich it with current `intel`
3. determine `exposure` in the environment
4. measure `detection` coverage
5. verify `validation` and testability
6. recommend `defense` and next actions

That gives the app a consistent answer to:

- what is happening
- why it matters
- whether it affects us
- whether we can see it
- whether we can test it
- what we should do next

## Workflow Buckets

### Behavior

Sources:

- `MITRE ATT&CK`

Role:

- primary navigation model
- common language for the whole app
- basis for matrix, actors, software, campaigns, and analytics

Typical workflow:

1. open a tactic or technique in the matrix
2. inspect linked actors, software, campaigns, and mitigations
3. branch into risk, detection, or planning workflows

Best UI surfaces:

- matrix
- sidebar
- actor and campaign views

### Intel

Sources:

- `OpenCTI`
- `MISP`
- supporting enrichment such as `MalwareBazaar`, `URLhaus`, and `AbuseIPDB`

Role:

- explain who is using a technique
- show evidence, attribution, confidence, and recency
- connect ATT&CK behaviors to current real-world reporting

#### OpenCTI workflow

Use OpenCTI for relationship-rich investigation.

1. start with a technique
2. load linked actors, malware, tools, and campaigns
3. show confidence, provenance, and last-seen context
4. let analysts pivot into actor compare, campaign timeline, and graph views

Best UI surfaces:

- actor profile
- actor compare
- campaign timeline
- technique graph

#### MISP workflow

Use MISP for event-driven intel and indicator-backed evidence.

1. start with a technique
2. load ATT&CK-tagged MISP events, tags, and attributes
3. highlight sightings and recent evidence
4. feed watchlists and "seen in current intel" filters

Best UI surfaces:

- sidebar
- watchlist
- campaign and actor views

#### MalwareBazaar / URLhaus / AbuseIPDB workflow

Use these as supplemental enrichment.

1. start with a software family, campaign, or technique
2. attach malware sample or infrastructure evidence
3. show supporting context, not primary product navigation

Best UI surfaces:

- sidebar enrichment
- software and campaign detail

### Exposure

Sources:

- `CVE`
- `NVD`
- `CPE`
- `CWE`
- `KEV`
- `EPSS`
- `SSVC`
- optional environment-backed scanning such as `OpenVAS` / `Greenbone`

Role:

- show whether a technique matters in a real environment
- connect ATT&CK behavior to vulnerabilities, products, and urgency
- support remediation and prioritization

#### CVE / NVD / CPE / CWE workflow

Use these together as the main exposure chain.

1. start with a technique
2. load mapped CVEs
3. resolve affected CPEs and products
4. group by CWE weakness families
5. rank exposure by severity, prevalence, and environment fit

Best UI surfaces:

- sidebar
- CVE panel
- risk views
- analytics

#### KEV workflow

Use KEV to indicate active exploitation pressure.

1. start with mapped CVEs
2. check whether each CVE is in KEV
3. raise priority for uncovered or weakly detected techniques

Best UI surfaces:

- risk matrix
- analytics
- sidebar badges

#### EPSS workflow

Use EPSS to estimate exploitation likelihood.

1. start with mapped CVEs
2. pull EPSS probabilities
3. combine with KEV and severity
4. rank techniques and exposures more realistically

Best UI surfaces:

- risk ranking
- analytics panel
- priority workflows

#### SSVC workflow

Use SSVC for decision framing rather than raw scoring.

1. start with exposure and operational context
2. evaluate urgency, impact, mission relevance, and exploitation status
3. recommend track, attend, or act-now style decisions

Best UI surfaces:

- priority panel
- executive or planning views

#### OpenVAS / Greenbone workflow

Use these to ground exposure in real scanning data.

1. start with known assets
2. import discovered vulnerabilities
3. map vulns to CVE, CPE, and ATT&CK relevance
4. prioritize techniques that are both exposed and operationally important

Best UI surfaces:

- risk workflows
- asset-aware exposure views

### Detection

Sources:

- `Sigma`
- `Zeek`
- `Suricata`
- `YARA`
- `CAR`
- optional stack-backed context from `Security Onion`
- endpoint visibility from `OSQuery` and `Wazuh`

Role:

- answer whether a technique is visible or detectable
- show what evidence sources exist
- guide engineering work to close coverage gaps

#### Sigma workflow

Use Sigma as the main open detection content layer.

1. start with a technique
2. load mapped Sigma rules
3. show counts, rule quality, and gaps
4. feed matrix heatmaps and sidebar detection sections

Best UI surfaces:

- matrix heatmaps
- detection panel
- sidebar
- analytics

#### Zeek workflow

Use Zeek for network observability context.

1. start with a technique
2. map required evidence to Zeek telemetry
3. indicate whether network-level visibility exists
4. recommend hunt or data-collection improvements

Best UI surfaces:

- data source panel
- detection panel
- sidebar data components

#### Suricata workflow

Use Suricata for network alert and signature coverage.

1. start with a technique
2. link it to available Suricata rules or categories
3. show where network IDS coverage exists or is absent

Best UI surfaces:

- detection panel
- analytics
- matrix overlays

#### YARA workflow

Use YARA for file and malware-oriented detection coverage.

1. start with a technique or software family
2. map file or payload detection opportunities
3. show whether malware-centric coverage exists

Best UI surfaces:

- sidebar
- detection views
- software workflows

#### CAR workflow

Use CAR to improve analytic strategy.

1. start with a technique
2. load related CAR analytics
3. turn ATT&CK behavior into concrete analytic ideas

Best UI surfaces:

- sidebar
- detection engineering workflows

#### OSQuery / Wazuh workflow

Use these for endpoint evidence and huntability.

1. start with a technique
2. map likely host artifacts and signals
3. show whether endpoint telemetry can observe those signals

Best UI surfaces:

- detection panel
- data source planning
- hunt workflows

#### Security Onion workflow

Use Security Onion as a practical open-stack reference.

1. start with a technique
2. show how a real open SOC stack could observe or alert on it
3. use it as a stack-level coverage view rather than a single-source feed

Best UI surfaces:

- detection readiness dashboards
- stack-level comparison views

### Validation

Sources:

- `Atomic Red Team`

Role:

- answer whether a technique can be exercised and tested
- turn coverage claims into something provable

Workflow:

1. start with a technique
2. load mapped Atomic tests
3. show supported platforms, prerequisites, and references
4. indicate whether the technique is testable and whether validation exists

Best UI surfaces:

- sidebar
- purple-team views
- dashboard
- scenario workflows

### Defense

Sources:

- `MITRE D3FEND`
- mitigations
- controls mappings
- `Engage`

Role:

- convert risk and coverage gaps into concrete defensive actions
- help users decide what to implement next

#### D3FEND workflow

Use D3FEND for countermeasure guidance.

1. start with a technique
2. map to defensive techniques or categories
3. show recommended countermeasures
4. connect those countermeasures to planning and coverage gaps

Best UI surfaces:

- sidebar
- controls panel
- planning and scenario views

#### Controls and mitigations workflow

Use these for program-level remediation.

1. start with an uncovered or exposed technique
2. review mitigations and control mappings
3. connect them to implementation status and documentation

Best UI surfaces:

- sidebar
- compliance views
- roadmap and planning panels

#### Engage workflow

Use Engage for planning-oriented defensive strategy.

1. start with a technique or actor context
2. load engagement or response guidance
3. use it to complement mitigations and D3FEND

Best UI surfaces:

- sidebar
- planning workflows

## End-To-End Analyst Workflow

The strongest cross-source workflow is:

1. `ATT&CK`
   - what is the behavior?
2. `OpenCTI` or `MISP`
   - who is using it and how current is the evidence?
3. `CVE/CPE/CWE`, `KEV`, `EPSS`, `SSVC`
   - are we exposed and how urgent is it?
4. `Sigma`, `Zeek`, `Suricata`, `YARA`, `CAR`, `OSQuery`, `Wazuh`
   - can we detect or observe it?
5. `Atomic Red Team`
   - can we test our detection and response?
6. `D3FEND`, mitigations, and controls
   - what should we implement next?

That is the difference between a reference tool and an operational workspace.

## Recommended Product Views

- `Matrix`
  - ATT&CK + urgency + coverage overlays
- `Sidebar`
  - one full coverage stack per technique
- `Risk views`
  - CVE, KEV, EPSS, SSVC, product relevance
- `Detection views`
  - Sigma, Zeek, Suricata, YARA, CAR, OSQuery, Wazuh
- `Threat views`
  - OpenCTI, MISP, actors, campaigns, malware
- `Validation views`
  - Atomic Red Team
- `Planning views`
  - D3FEND, controls, mitigations, implementation state

## Best Design Rule

Avoid creating one isolated panel for every source unless the workflow truly demands it.

Prefer one consistent technique-centered coverage stack:

- `behavior`
- `intel`
- `exposure`
- `detection`
- `validation`
- `defense`

That keeps the app matrix-first and makes the data easier to navigate as it grows.
