# Mappings Cheat Sheet

## Goal

This app should use ATT&CK as the center of the experience and enrich it with related cyber knowledge systems that answer:

- what behavior is happening
- what weakness or vulnerability enables it
- what products are affected
- what defensive action should counter it

## Core Systems

### MITRE ATT&CK

What it is:

- adversary tactics, techniques, software, groups, and campaigns

How the app should use it:

- primary matrix navigation model
- base graph for techniques, tactics, groups, campaigns, and software
- main source of panel routing and matrix heatmaps

Where to get it:

- [ATT&CK Data and Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- [ATT&CK GitHub organization](https://github.com/mitre-attack)
- [ATT&CK Data Model schemas](https://mitre-attack.github.io/attack-data-model/schemas/)

### CAPEC

What it is:

- Common Attack Pattern Enumeration and Classification
- attack-pattern catalog

How the app should use it:

- explain attack-pattern context behind ATT&CK techniques
- enrich technique sidebars and scenario views
- support "related attack patterns" exploration

Where to get it:

- [CAPEC](https://capec.mitre.org/)

### CWE

What it is:

- Common Weakness Enumeration
- weakness classes such as injection, improper validation, deserialization, and memory corruption

How the app should use it:

- explain why a technique or exploit works
- group related CVEs by weakness family
- support remediation and architecture analysis

Where to get it:

- [CWE Downloads](https://cwe.mitre.org/data/downloads.html)

### CVE

What it is:

- Common Vulnerabilities and Exposures
- specific public vulnerability records

How the app should use it:

- exposure overlays
- urgency and risk prioritization
- technique-linked vulnerability evidence

Where to get it:

- [CVE Program](https://www.cve.org/)
- [CVE List V5](https://github.com/CVEProject/cvelistV5)

### CPE

What it is:

- Common Platform Enumeration
- standardized product and platform naming

How the app should use it:

- product impact analysis
- asset-aware exposure views
- environmental relevance ranking

Where to get it:

- [NVD CPE](https://nvd.nist.gov/Products/CPE)
- [NVD CPE Search](https://nvd.nist.gov/products/cpe/search)

### MITRE D3FEND

What it is:

- defensive countermeasure knowledge base

How the app should use it:

- recommend defensive actions for ATT&CK techniques
- strengthen controls, remediation, and planning workflows
- improve "what do we do next?" guidance

Where to get it:

- [D3FEND Ontology Resources](https://d3fend.mitre.org/resources/ontology/)
- [D3FEND GitHub organization](https://github.com/d3fend)

## The Most Important Mappings

### CVE -> CWE

Meaning:

- this vulnerability is caused by this weakness type

Why it matters:

- converts a long list of vulnerabilities into root-cause groupings

Best app usage:

- sidebar vulnerability analysis
- weakness rollups
- remediation strategy

### CVE -> CPE

Meaning:

- this vulnerability affects these products and versions

Why it matters:

- tells you whether a vulnerability is relevant to a real environment

Best app usage:

- asset-aware prioritization
- product impact filtering
- environment-specific risk scoring

### CWE -> CAPEC

Meaning:

- this weakness is commonly exploited through these attack patterns

Why it matters:

- bridges implementation weakness to attacker tradecraft

Best app usage:

- weakness-to-attack explanation
- scenario planning
- analyst drill-down

### CAPEC -> ATT&CK

Meaning:

- this attack pattern aligns with these ATT&CK techniques

Why it matters:

- bridges abstract patterns to operational ATT&CK behaviors

Best app usage:

- sidebar context
- attack-pattern exploration
- scenario and actor workflows

### ATT&CK -> D3FEND

Meaning:

- these defensive techniques help counter this attacker behavior

Why it matters:

- turns ATT&CK into actionable defense planning

Best app usage:

- remediation guidance
- controls and coverage planning
- risk workflow next steps

## Recommended App Data Flow

Use this as the conceptual model:

1. Load ATT&CK as the base graph
2. Enrich ATT&CK techniques with CVE evidence
3. Link CVEs to CWEs and CPEs
4. Link CWEs to CAPEC attack patterns
5. Link ATT&CK techniques to D3FEND defensive techniques

That creates a clean chain:

- behavior
- vulnerability
- weakness
- affected product
- attack pattern
- defensive response

## Best Internal Model For This App

Instead of treating each source as a one-off panel, normalize them into internal categories:

- `behavior`
  - ATT&CK
- `exposure`
  - CVE
- `weakness`
  - CWE
- `product`
  - CPE
- `attack_pattern`
  - CAPEC
- `defense`
  - D3FEND

Then add relationship types such as:

- `enables`
- `affects`
- `caused_by`
- `maps_to`
- `countered_by`
- `observed_in`

## Best UI Use Per Source

### Matrix

- ATT&CK remains the main matrix
- CVE and KEV influence urgency overlays
- D3FEND can influence defense guidance heatmaps

### Sidebar

- best place for CAPEC, CWE, CVE, CPE, and D3FEND drill-down

### Risk Views

- CVE, KEV, and CPE should strongly influence rank and urgency

### Controls / Planning Views

- D3FEND and mitigations should drive recommendations

## Full Data and Repo Sources

- ATT&CK:
  - [ATT&CK Data and Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
  - [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
  - [ATT&CK Data Model schemas](https://mitre-attack.github.io/attack-data-model/schemas/)

- CAPEC:
  - [CAPEC](https://capec.mitre.org/)

- CWE:
  - [CWE Downloads](https://cwe.mitre.org/data/downloads.html)

- CVE:
  - [CVE Program](https://www.cve.org/)
  - [CVE List V5](https://github.com/CVEProject/cvelistV5)

- CPE:
  - [NVD CPE](https://nvd.nist.gov/Products/CPE)
  - [NVD CPE Search](https://nvd.nist.gov/products/cpe/search)

- D3FEND:
  - [D3FEND Ontology Resources](https://d3fend.mitre.org/resources/ontology/)
  - [D3FEND GitHub organization](https://github.com/d3fend)

## Recommended First Implementation

If these mappings are built into the app, start with:

1. ATT&CK base graph
2. CVE -> CWE
3. CVE -> CPE
4. ATT&CK -> D3FEND
5. CWE -> CAPEC
6. CAPEC -> ATT&CK

That order gives the fastest return for risk, exposure, and defensive guidance.
