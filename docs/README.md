# ATTACK-Navi Docs Index

This folder and the root technical documents together form the project handbook for ATTACK-Navi.

If you are new to the repo, start in this order:

1. [README](../README.md)
2. [Application Overview](application-overview.md)
3. [Architecture](../ARCHITECTURE.md)
4. [Workflows](../WORKFLOWS.md)
5. [Data Source Scorecard](../DATA_SOURCE_SCORECARD.md)
6. [Heatmaps](HEATMAPS.md)
7. [Services](SERVICES.md)
8. [Components](COMPONENTS.md)
9. [Configuration](CONFIGURATION.md)
10. [Security](../SECURITY.md)

## Documentation Map

### Product and analyst workflows

- [Application Overview](application-overview.md)
  Product-level summary of the app, its strongest workflows, and its current boundaries.
- [Workflows](../WORKFLOWS.md)
  End-to-end analyst paths across behavior, intelligence, exposure, detection, validation, and defense.
- [Data Source Scorecard](../DATA_SOURCE_SCORECARD.md)
  Status of live, bundled, and planned data integrations.
- [Mappings Cheat Sheet](../MAPPINGS_CHEAT_SHEET.md)
  Quick reference for ATT&CK-adjacent mapping systems and terminology.

### Architecture and implementation

- [Architecture](../ARCHITECTURE.md)
  State management, component orchestration, and data-loading patterns.
- [Heatmaps](HEATMAPS.md)
  Heatmap intent, scoring behavior, and mode-specific notes.
- [Services](SERVICES.md)
  Service responsibilities, integration helpers, and runtime data roles.
- [Components](COMPONENTS.md)
  Component-level notes for the Angular UI surface.
- [Configuration](CONFIGURATION.md)
  Local settings, deployment knobs, and integration setup details.

### Operations and contribution

- [Security](../SECURITY.md)
  Deployment posture, vulnerability reporting, and integration safety guidance.
- [Contributing](../CONTRIBUTING.md)
  Development setup and contributor expectations.
- [Server README](../server/README.md)
  Optional backend proxy notes for OpenCTI and MISP secret handling.
- [Open Source Integrations](../OPEN_SOURCE_INTEGRATIONS.md)
  Expansion ideas for future integrations and adjacent tooling.

## Quick Orientation

ATTACK-Navi is strongest when it is used as an analysis surface rather than a static ATT&CK viewer:

- compare coverage and control depth across tactics
- pivot from techniques into threat groups, campaigns, software, and indicators
- connect exposure evidence and detection content to specific ATT&CK techniques
- export findings into review-ready artifacts

## Documentation Standards

When adding new docs:

- describe current behavior before describing future intent
- distinguish live data from bundled or derived data
- call out partial coverage honestly when a mapping or integration is incomplete
- keep workflow and panel names consistent with the running application
