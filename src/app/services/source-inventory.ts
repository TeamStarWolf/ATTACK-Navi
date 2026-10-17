// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The source inventory: one SourceDefinition per data source the app ships or
// fetches, keyed to the rows of product plan section 6.3. SourceRegistryService
// turns these into live SourceRecords. When a loader or a bundled file is added,
// add its definition here; source-registry.service.spec.ts fails until the
// section 6.3 list and this file agree, and source-honesty.spec.ts fails until a
// new live source has a forced-failure case.
//
// Dates: `reviewedDate` for a project file is the last commit date of that file
// (`git log -1 --format=%cs -- <file>`) when this inventory was written.
import { LicenceNote, LicenceNoteId, SourceDefinition } from '../models/source-record';

/** Rows of the section 6.3 inventory table, by their "Source" column. */
export const INVENTORY_ROW = {
  attackBundles: 'ATT&CK Enterprise / ICS / Mobile / F3 bundles',
  atlas: 'ATLAS',
  cveTechniqueMap: 'cve-technique-map.json (CVE to CWE to CAPEC to ATT&CK)',
  cve2capecRuntime: 'CVE2CAPEC runtime fetch',
  ctidAttackToCve: 'CTID attack_to_cve',
  kev: 'CISA KEV',
  epssNvd: 'EPSS, NVD',
  ctidMappings: 'CTID mappings (NIST 800-53, CRI, CSA CCM, VERIS, AWS, Azure, GCP, M365)',
  cis: 'CIS Controls',
  referenceRuntime: 'Sigma coverage, CAR, Atomic, CAPEC, MISP galaxy, Engage',
  vendorRuleTrees: 'Elastic, Splunk, Sentinel (edoardogerosa)',
  m365Hunting: 'M365 Defender hunting queries',
  trickest: 'trickest PoC tree',
  nuclei: 'Nuclei templates',
  communityHunting: 'mdecrevoisier Sigma, Threat-Hunting',
  evtx: 'EVTX samples',
  offensive: 'PayloadsAllTheThings, ExploitDB, offensive tools',
  ipsum: 'ipsum IP reputation list',
  threatHunterPlaybook: 'ThreatHunter Playbook layer',
  mukul975: 'mukul975 third-party layer',
  cweCatalog: 'cwe-catalog.json',
  cweAnchor: 'cwe-exploitation-anchor.json',
  techniqueQueries: 'technique-queries.json',
  ssvcTables: 'ssvc-decision-tables.json',
  dossiers: 'CVE dossiers (22 files, newest CVE-2024-21893)',
  d3fendSeed: 'D3FEND seed',
  curatedTables: 'CAR seed, Wazuh stock-rule table (~22 ids), YARA, Zeek, Suricata, event-logging, IR playbooks',
  library: 'Library layers and library.json',
  lylat: 'Lylat mission layers',
} as const;

/** A source the app uses that section 6.3 does not list. */
export const NOT_IN_INVENTORY = 'not in 6.3';

/**
 * The ATT&CK release shipped in src/assets/data. Bump together with a data refresh;
 * bundled-data.spec.ts checks it against the bundles' x-mitre-collection version.
 */
export const BUNDLED_ATTACK_VERSION = '19.2';
/** The F3 release shipped in src/assets/data/f3-attack.json (checked by bundled-data.spec.ts). */
export const BUNDLED_F3_VERSION = '1.2';

/**
 * The bundled KEV snapshot (src/assets/data/kev-snapshot.json), pinned by date by
 * scripts/build-kev-snapshot.mjs. Bump together with a new snapshot; kev-snapshot.spec.ts
 * and scripts/build-kev-snapshot.test.mjs check these against the file's __meta.
 */
export const BUNDLED_KEV_SNAPSHOT = {
  date: '2026-10-16',
  catalogVersion: '2026.10.16',
  commit: '6a392940c663b52271fa4e6aa7b39995b18c9a71',
} as const;

/** Licence notes, keyed by the id each SourceDefinition carries. */
export const LICENCE_NOTES: Record<LicenceNoteId, LicenceNote> = {
  'attack': { licence: 'ATT&CK licence (MITRE)', notice: 'THIRD_PARTY_NOTICES.md section 1.1' },
  'f3-apache-2.0': { licence: 'Apache License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 1.2' },
  'cwe': { licence: 'CWE terms of use (MITRE)', notice: 'THIRD_PARTY_NOTICES.md section 1.3' },
  'capec': { licence: 'CAPEC terms of use (MITRE)', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'ssvc-sei-mit': { licence: 'MIT (SEI)-style licence (CERT/CC SSVC data)', notice: 'THIRD_PARTY_NOTICES.md section 1.4' },
  'nvd': { licence: 'NVD terms of use', notice: 'THIRD_PARTY_NOTICES.md section 1.5' },
  'cve': { licence: 'CVE terms of use (MITRE)', notice: 'THIRD_PARTY_NOTICES.md section 1.5' },
  'epss': { licence: 'FIRST EPSS, free to use with attribution', notice: 'THIRD_PARTY_NOTICES.md section 1.5' },
  'kev-cc0': { licence: 'CC0 1.0 Universal (CISA KEV)', notice: 'THIRD_PARTY_NOTICES.md section 1.5' },
  'd3fend': { licence: 'D3FEND terms of use (MITRE)', notice: 'THIRD_PARTY_NOTICES.md section 1.6' },
  'car-apache-2.0': { licence: 'Apache License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 1.7' },
  'engage-apache-2.0': { licence: 'Apache License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'ctid-apache-2.0': { licence: 'Apache License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'atomic-mit': { licence: 'MIT License', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'sigma-drl-1.1': { licence: 'Detection Rule License 1.1', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'mdecrevoisier-cc0': { licence: 'CC0 1.0 Universal', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'otrf-mit': { licence: 'MIT License', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'misp-cc0-mit': { licence: 'CC0 1.0 Universal or MIT-style', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'trickest-mit': { licence: 'MIT License', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'galeax-gpl-3.0': { licence: 'GNU GPL v3.0', notice: 'THIRD_PARTY_NOTICES.md section 2 (bundled map: decision D11)' },
  'ipsum-unlicense': { licence: 'The Unlicense', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'payloads-mit': { licence: 'MIT License', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'mukul975-apache-2.0': { licence: 'Apache License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'exploitdb-terms': { licence: "Exploit-DB's own terms", notice: 'THIRD_PARTY_NOTICES.md section 2' },
  'elastic-license-2.0': { licence: 'Elastic License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 1.8 (runtime tree listing not yet in section 2)' },
  'splunk-apache-2.0': { licence: 'Apache License 2.0', notice: 'THIRD_PARTY_NOTICES.md section 1.8 (runtime tree listing not yet in section 2)' },
  'm365-hunting-mit': { licence: 'MIT License', notice: 'THIRD_PARTY_NOTICES.md section 1.8 (runtime tree listing not yet in section 2)' },
  'sentinel-attack-mit': { licence: 'MIT License (per GitHub)', notice: 'not yet in THIRD_PARTY_NOTICES.md' },
  'cyb3r-monk-bsd-3': { licence: 'BSD 3-Clause (per GitHub)', notice: 'not yet in THIRD_PARTY_NOTICES.md' },
  'nuclei-mit': { licence: 'MIT License (per GitHub)', notice: 'not yet in THIRD_PARTY_NOTICES.md' },
  'query-library': { licence: 'project work; reproduced upstream rules keep their licence', notice: 'THIRD_PARTY_NOTICES.md section 1.8' },
  'project-mit': { licence: 'MIT License (this project)', notice: 'THIRD_PARTY_NOTICES.md section 1.10' },
};

const R = INVENTORY_ROW;
const CTID_RAW = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings';

/** Every source the app ships or fetches. Order follows section 6.3. */
export const SOURCE_DEFINITIONS: readonly SourceDefinition[] = [
  // ── ATT&CK and F3 ──────────────────────────────────────────────────────────
  {
    id: 'attack-enterprise', name: 'ATT&CK Enterprise (bundled)', kind: 'bundled',
    version: BUNDLED_ATTACK_VERSION, upstream: 'https://github.com/mitre-attack/attack-stix-data',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/data.service.ts',
  },
  {
    id: 'attack-ics', name: 'ATT&CK for ICS (bundled)', kind: 'bundled',
    version: BUNDLED_ATTACK_VERSION, upstream: 'https://github.com/mitre-attack/attack-stix-data',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/data.service.ts', onDemand: true,
  },
  {
    id: 'attack-mobile', name: 'ATT&CK Mobile (bundled)', kind: 'bundled',
    version: BUNDLED_ATTACK_VERSION, upstream: 'https://github.com/mitre-attack/attack-stix-data',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/data.service.ts', onDemand: true,
  },
  {
    id: 'attack-f3', name: 'CTID F3 Fraud Framework (bundled)', kind: 'bundled',
    version: BUNDLED_F3_VERSION, upstream: 'https://github.com/center-for-threat-informed-defense/fight-fraud-framework',
    licence: 'f3-apache-2.0', inventoryRow: R.attackBundles,
    owner: 'services/data.service.ts, services/f3-fraud.service.ts', onDemand: true,
  },
  {
    id: 'attack-live-enterprise', name: 'ATT&CK Enterprise (live)', kind: 'live',
    version: 'master, unpinned', upstream: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/data.service.ts',
    note: 'Live mode only; E1.4 turns this into "check for update" (decision D2).',
  },
  {
    id: 'attack-live-ics', name: 'ATT&CK for ICS (live)', kind: 'live',
    version: 'master, unpinned', upstream: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/data.service.ts', onDemand: true,
  },
  {
    id: 'attack-live-mobile', name: 'ATT&CK Mobile (live)', kind: 'live',
    version: 'master, unpinned', upstream: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/data.service.ts', onDemand: true,
  },
  {
    id: 'attack-live-f3', name: 'CTID F3 Fraud Framework (live)', kind: 'live',
    version: 'main, unpinned', upstream: 'https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json',
    licence: 'f3-apache-2.0', inventoryRow: R.attackBundles, owner: 'services/data.service.ts', onDemand: true,
  },
  {
    id: 'attack-releases', name: 'ATT&CK release list (GitHub API)', kind: 'live',
    version: 'latest 5 releases', upstream: 'https://api.github.com/repos/mitre-attack/attack-stix-data/releases',
    licence: 'attack', inventoryRow: R.attackBundles, owner: 'services/changelog.service.ts',
  },

  // ── CVE chain ──────────────────────────────────────────────────────────────
  {
    id: 'cve-technique-map', name: 'CVE to technique map (bundled)', kind: 'bundled',
    version: 'generated 2026-10-13 from Galeax/CVE2CAPEC@main (unpinned), ATT&CK 19.2',
    upstream: 'https://github.com/Galeax/CVE2CAPEC', licence: 'galeax-gpl-3.0',
    inventoryRow: R.cveTechniqueMap, owner: 'services/nvd-bulk.service.ts',
  },
  {
    id: 'cve-technique-counts', name: 'CVE to technique counts (bundled)', kind: 'bundled',
    reviewedDate: '2026-04-05', upstream: 'https://github.com/Galeax/CVE2CAPEC', licence: 'galeax-gpl-3.0',
    inventoryRow: R.cveTechniqueMap, owner: 'src/assets/data/cve-technique-counts.json',
    note: 'Shipped but read by no code path.',
  },
  {
    id: 'cve2capec-runtime', name: 'CVE2CAPEC database (runtime)', kind: 'live',
    version: 'main, unpinned (current and previous year files)', upstream: 'https://github.com/Galeax/CVE2CAPEC',
    licence: 'galeax-gpl-3.0', inventoryRow: R.cve2capecRuntime, owner: 'services/cve2capec.service.ts',
  },
  {
    id: 'ctid-attack-to-cve', name: 'CTID ATT&CK to CVE mappings', kind: 'live',
    version: 'master, unpinned (repository archived)',
    upstream: 'https://github.com/center-for-threat-informed-defense/attack_to_cve',
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidAttackToCve, owner: 'services/attack-cve.service.ts',
    archivedUpstream: '2024-04-03',
  },
  {
    id: 'cisa-kev', name: 'CISA Known Exploited Vulnerabilities', kind: 'live',
    version: 'develop, unpinned (cisagov/kev-data mirror; cisa.gov feed as fallback)',
    upstream: 'https://github.com/cisagov/kev-data', licence: 'kev-cc0',
    inventoryRow: R.kev, owner: 'services/cve.service.ts',
  },
  {
    id: 'cisa-kev-snapshot', name: 'CISA KEV snapshot (bundled)', kind: 'bundled',
    version: `snapshot of ${BUNDLED_KEV_SNAPSHOT.date}, catalogVersion ${BUNDLED_KEV_SNAPSHOT.catalogVersion} (cisagov/kev-data@${BUNDLED_KEV_SNAPSHOT.commit.slice(0, 7)})`,
    upstream: 'https://github.com/cisagov/kev-data', licence: 'kev-cc0',
    inventoryRow: R.kev, owner: 'services/cve.service.ts', onDemand: true, fallbackFor: 'cisa-kev',
    note: 'Read only when the live KEV feed fails; built by scripts/build-kev-snapshot.mjs. A CVE added to KEV after the snapshot date is not in it.',
  },
  {
    id: 'epss', name: 'FIRST EPSS API', kind: 'live', version: 'API v1 (current scores)',
    upstream: 'https://api.first.org/data/v1/epss', licence: 'epss',
    inventoryRow: R.epssNvd, owner: 'services/epss.service.ts', onDemand: true,
  },
  {
    id: 'nvd', name: 'NIST NVD CVE API', kind: 'live', version: 'CVE API 2.0',
    upstream: 'https://services.nvd.nist.gov/rest/json/cves/2.0', licence: 'nvd',
    inventoryRow: R.epssNvd, owner: 'services/cve.service.ts', onDemand: true,
  },
  {
    id: 'cve-services', name: 'CVE Services record API (CISA ADP SSVC)', kind: 'live', version: 'CVE Services API, current records',
    upstream: 'https://cveawg.mitre.org/api/cve', licence: 'cve',
    inventoryRow: NOT_IN_INVENTORY, owner: 'services/cisa-ssvc.service.ts', onDemand: true,
  },

  // ── CTID mappings ──────────────────────────────────────────────────────────
  {
    id: 'ctid-nist-800-53', name: 'CTID NIST 800-53 rev5 mapping', kind: 'live',
    version: 'nist_800_53-rev5, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/nist-mapping.service.ts',
  },
  {
    id: 'ctid-cri-profile', name: 'CTID CRI Profile mapping', kind: 'live',
    version: 'cri_profile-v2.1, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/cri_profile/attack-16.1/cri_profile-v2.1/enterprise/cri_profile-v2.1_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/cri-profile.service.ts',
  },
  {
    id: 'ctid-csa-ccm', name: 'CTID CSA CCM mapping', kind: 'live',
    version: 'csa_ccm-4.1, mapped vs ATT&CK 17.1', upstream: `${CTID_RAW}/csa_ccm/attack-17.1/csa_ccm-4.1/enterprise/csa_ccm-4.1_attack-17.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/csa-ccm.service.ts',
  },
  {
    id: 'ctid-veris', name: 'CTID VERIS mapping', kind: 'live',
    version: 'veris-1.4.0, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/veris/attack-16.1/veris-1.4.0/enterprise/veris-1.4.0_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/veris.service.ts',
  },
  {
    id: 'ctid-aws', name: 'CTID AWS mapping', kind: 'live',
    version: 'aws-12.12.2024, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/aws/attack-16.1/aws-12.12.2024/enterprise/aws-12.12.2024_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/cloud-controls.service.ts',
  },
  {
    id: 'ctid-azure', name: 'CTID Azure mapping', kind: 'live',
    version: 'azure-04.26.2025, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/azure/attack-16.1/azure-04.26.2025/enterprise/azure-04.26.2025_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/cloud-controls.service.ts',
  },
  {
    id: 'ctid-gcp', name: 'CTID GCP mapping', kind: 'live',
    version: 'gcp-03.06.2025, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/gcp/attack-16.1/gcp-03.06.2025/enterprise/gcp-03.06.2025_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/cloud-controls.service.ts',
  },
  {
    id: 'ctid-m365', name: 'CTID M365 mapping', kind: 'live',
    version: 'm365-07.18.2025, mapped vs ATT&CK 16.1', upstream: `${CTID_RAW}/m365/attack-16.1/m365-07.18.2025/enterprise/m365-07.18.2025_attack-16.1-enterprise.json`,
    licence: 'ctid-apache-2.0', inventoryRow: R.ctidMappings, owner: 'services/m365-controls.service.ts',
  },
  {
    id: 'ctid-kev', name: 'CTID KEV mapping', kind: 'live',
    version: 'newest snapshot in mappings-explorer (pinned fallback kev-07.28.2025, mapped vs ATT&CK 16.1)',
    upstream: `${CTID_RAW}/kev`, licence: 'ctid-apache-2.0',
    inventoryRow: R.ctidMappings, owner: 'services/attack-cve.service.ts',
  },
  {
    id: 'cis-controls', name: 'CIS Controls mapping', kind: 'live',
    version: 'none (no upstream file since ATT&CK 16)', upstream: 'https://github.com/center-for-threat-informed-defense/mappings-explorer',
    licence: 'ctid-apache-2.0', inventoryRow: R.cis, owner: 'services/cis-controls.service.ts',
    initialStatus: 'archived-upstream',
    note: 'Source withdrawn upstream: CTID removed the CIS mappings from mappings-explorer as of ATT&CK 16; the service loads nothing.',
  },

  // ── Reference content fetched at runtime ───────────────────────────────────
  {
    id: 'sigmahq-coverage', name: 'SigmaHQ coverage layer', kind: 'live', version: 'master, unpinned',
    upstream: 'https://raw.githubusercontent.com/SigmaHQ/sigma/master/other/sigma_attack_nav_coverage.json',
    licence: 'sigma-drl-1.1', inventoryRow: R.referenceRuntime, owner: 'services/sigma.service.ts',
  },
  {
    id: 'car-layer', name: 'MITRE CAR navigator layer', kind: 'live', version: 'master, unpinned',
    upstream: 'https://raw.githubusercontent.com/mitre-attack/car/master/docs/car_attack/car_attack.json',
    licence: 'car-apache-2.0', inventoryRow: R.referenceRuntime, owner: 'services/car.service.ts',
    note: 'CAR maps against old ATT&CK ids (v14); remapping arrives with E3.1.',
  },
  {
    id: 'atomic-layer', name: 'Atomic Red Team navigator layer', kind: 'live', version: 'master, unpinned',
    upstream: 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Attack-Navigator-Layers/art-navigator-layer.json',
    licence: 'atomic-mit', inventoryRow: R.referenceRuntime, owner: 'services/atomic.service.ts',
  },
  {
    id: 'atomic-tests', name: 'Atomic Red Team per-technique tests', kind: 'live', version: 'master, unpinned',
    upstream: 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics', licence: 'atomic-mit',
    inventoryRow: R.referenceRuntime, owner: 'services/atomic.service.ts', onDemand: true,
  },
  {
    id: 'capec', name: 'CAPEC STIX (mitre/cti)', kind: 'live', version: 'CAPEC STIX 2.1, master, unpinned',
    upstream: 'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json',
    licence: 'capec', inventoryRow: R.referenceRuntime, owner: 'services/capec.service.ts',
  },
  {
    id: 'misp-galaxy', name: 'MISP galaxy (mitre-attack-pattern)', kind: 'live', version: 'main, unpinned',
    upstream: 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json',
    licence: 'misp-cc0-mit', inventoryRow: R.referenceRuntime, owner: 'services/misp.service.ts',
  },
  {
    id: 'engage', name: 'MITRE Engage', kind: 'live', version: 'main, unpinned',
    upstream: 'https://github.com/mitre/engage', licence: 'engage-apache-2.0',
    inventoryRow: R.referenceRuntime, owner: 'services/engage.service.ts',
    note: 'Upstream last pushed 2024-04-01; the repository is not archived on GitHub.',
  },
  {
    id: 'elastic-tree', name: 'Elastic detection-rules (tree listing)', kind: 'live', version: 'main, unpinned',
    upstream: 'https://github.com/elastic/detection-rules', licence: 'elastic-license-2.0',
    inventoryRow: R.vendorRuleTrees, owner: 'services/elastic.service.ts',
    note: 'Technique ids are read from file paths, which rarely carry them; an empty result is reported as empty.',
  },
  {
    id: 'splunk-tree', name: 'Splunk security_content (tree listing)', kind: 'live', version: 'develop, unpinned',
    upstream: 'https://github.com/splunk/security_content', licence: 'splunk-apache-2.0',
    inventoryRow: R.vendorRuleTrees, owner: 'services/splunk-content.service.ts',
    note: 'Technique ids are read from file paths, which rarely carry them; an empty result is reported as empty.',
  },
  {
    id: 'sentinel-attack-tree', name: 'edoardogerosa/sentinel-attack (tree listing)', kind: 'live', version: 'master, unpinned',
    upstream: 'https://github.com/edoardogerosa/sentinel-attack', licence: 'sentinel-attack-mit',
    inventoryRow: R.vendorRuleTrees, owner: 'services/sentinel-rules.service.ts', onDemand: true,
  },
  {
    id: 'm365-hunting-queries', name: 'Microsoft 365 Defender hunting queries (tree listing)', kind: 'live',
    version: 'master, unpinned (repository archived)', upstream: 'https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries',
    licence: 'm365-hunting-mit', inventoryRow: R.m365Hunting, owner: 'services/m365-defender.service.ts',
    onDemand: true, archivedUpstream: '2022-02-17',
  },
  {
    id: 'trickest-poc-tree', name: 'trickest/cve PoC index (tree listing)', kind: 'live', version: 'main, unpinned',
    upstream: 'https://github.com/trickest/cve', licence: 'trickest-mit',
    inventoryRow: R.trickest, owner: 'services/poc-exploit.service.ts',
  },
  {
    id: 'nuclei-tree', name: 'Nuclei templates (tree listing)', kind: 'live', version: 'main, unpinned',
    upstream: 'https://github.com/projectdiscovery/nuclei-templates', licence: 'nuclei-mit',
    inventoryRow: R.nuclei, owner: 'services/nuclei.service.ts', onDemand: true,
  },
  {
    id: 'mdecrevoisier-sigma-tree', name: 'mdecrevoisier SIGMA-detection-rules (tree listing)', kind: 'live', version: 'main, unpinned',
    upstream: 'https://github.com/mdecrevoisier/SIGMA-detection-rules', licence: 'mdecrevoisier-cc0',
    inventoryRow: R.communityHunting, owner: 'services/sigma.service.ts', onDemand: true,
  },
  {
    id: 'cyb3r-monk-hunting-tree', name: 'Cyb3r-Monk Threat-Hunting-and-Detection (tree listing)', kind: 'live', version: 'main, unpinned',
    upstream: 'https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection', licence: 'cyb3r-monk-bsd-3',
    inventoryRow: R.communityHunting, owner: 'services/threat-hunting.service.ts', onDemand: true,
  },
  {
    id: 'evtx-samples-tree', name: 'mdecrevoisier EVTX-to-MITRE-Attack (tree listing)', kind: 'live', version: 'master, unpinned',
    upstream: 'https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack', licence: 'mdecrevoisier-cc0',
    inventoryRow: R.evtx, owner: 'services/evtx-samples.service.ts', onDemand: true,
  },
  {
    id: 'payloads-tree', name: 'PayloadsAllTheThings (tree listing)', kind: 'live', version: 'master, unpinned',
    upstream: 'https://github.com/swisskyrepo/PayloadsAllTheThings', licence: 'payloads-mit',
    inventoryRow: R.offensive, owner: 'services/payloads.service.ts', onDemand: true,
  },
  {
    id: 'payloads-folder-map', name: 'PayloadsAllTheThings folder-to-technique map', kind: 'project-authored',
    reviewedDate: '2026-08-14', upstream: 'no upstream', licence: 'project-mit',
    inventoryRow: R.offensive, owner: 'services/payloads.service.ts', initialStatus: 'loaded',
    note: 'Curated attribution used when the tree listing cannot be fetched.',
  },
  {
    id: 'exploitdb', name: 'Exploit Database CSV', kind: 'live', version: 'main, unpinned',
    upstream: 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
    licence: 'exploitdb-terms', inventoryRow: R.offensive, owner: 'services/exploitdb.service.ts', onDemand: true,
  },
  {
    id: 'offensive-tools', name: 'Offensive tools list', kind: 'project-authored',
    reviewedDate: '2026-08-14', upstream: 'no upstream', licence: 'project-mit',
    inventoryRow: R.offensive, owner: 'services/offensive-tools.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'ipsum', name: 'stamparm/ipsum IP reputation (level 3)', kind: 'live', version: 'master, unpinned',
    upstream: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
    licence: 'ipsum-unlicense', inventoryRow: R.ipsum, owner: 'services/ioc-feed.service.ts', onDemand: true,
    note: 'IP reputation only; no technique mapping.',
  },
  {
    id: 'threathunter-playbook', name: 'OTRF ThreatHunter-Playbook layer', kind: 'live', version: 'main, unpinned (layer written for ATT&CK v10)',
    upstream: 'https://github.com/OTRF/ThreatHunter-Playbook', licence: 'otrf-mit',
    inventoryRow: R.threatHunterPlaybook, owner: 'services/threathunter-playbook.service.ts',
  },
  {
    id: 'anthropic-skills-layer', name: 'mukul975/Anthropic-Cybersecurity-Skills layer', kind: 'live', version: 'main, unpinned',
    upstream: 'https://raw.githubusercontent.com/mukul975/Anthropic-Cybersecurity-Skills/main/mappings/attack-navigator-layer.json',
    licence: 'mukul975-apache-2.0', inventoryRow: R.mukul975, owner: 'services/anthropic-skills.service.ts',
  },

  // ── Bundled and project files ──────────────────────────────────────────────
  {
    id: 'cwe-catalog', name: 'CWE catalog (bundled)', kind: 'bundled', reviewedDate: '2026-04-04',
    upstream: 'https://cwe.mitre.org/', licence: 'cwe', inventoryRow: R.cweCatalog, owner: 'services/cwe.service.ts',
    note: 'No CWE version stamp in the file; the date is its last commit.',
  },
  {
    id: 'cwe-seed', name: 'CWE short-name table', kind: 'seed', reviewedDate: '2026-04-04',
    upstream: 'https://cwe.mitre.org/', licence: 'cwe', inventoryRow: NOT_IN_INVENTORY,
    owner: 'services/cwe.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'cwe-exploitation-anchor', name: 'CWE to ATT&CK exploitation anchor', kind: 'project-authored',
    reviewedDate: '2026-09-27', upstream: 'no upstream', licence: 'project-mit',
    inventoryRow: R.cweAnchor, owner: 'services/cve.service.ts',
    note: 'Curated edges; also read by scripts/build-cve-technique-map.mjs.',
  },
  {
    id: 'technique-queries', name: 'Per-technique SIEM query library', kind: 'project-authored',
    reviewedDate: '2026-04-17', upstream: 'no upstream', licence: 'query-library',
    inventoryRow: R.techniqueQueries, owner: 'services/siem-query.service.ts',
    note: 'Curated, 13 techniques.',
  },
  {
    id: 'ssvc-tables', name: 'SSVC decision tables (bundled)', kind: 'bundled',
    version: 'generated 2026-09-24; CISA Coordinator v2.0.3, BOD 26-04 v1.0.0',
    upstream: 'https://github.com/CERTCC/SSVC', licence: 'ssvc-sei-mit',
    inventoryRow: R.ssvcTables, owner: 'services/ssvc.service.ts',
  },
  {
    id: 'cve-dossiers', name: 'Pre-built CVE dossiers (index)', kind: 'bundled', reviewedDate: '2026-09-23',
    upstream: 'no upstream', licence: 'nvd', inventoryRow: R.dossiers, owner: 'services/dossier.service.ts',
    note: 'Generated in this repository by a manual generator from NVD, EPSS and KEV; 20 dossier files plus index.json on main.',
  },
  {
    id: 'd3fend-seed', name: 'D3FEND countermeasure seed', kind: 'seed', version: 'pruned against D3FEND 1.4.0',
    reviewedDate: '2026-10-16', upstream: 'https://d3fend.mitre.org/', licence: 'd3fend',
    inventoryRow: R.d3fendSeed, owner: 'services/d3fend.service.ts', initialStatus: 'stale',
    note: 'Upstream ontology is at 1.6.0; the live index reconciles the seed at startup.',
  },
  {
    id: 'd3fend-ontology', name: 'D3FEND technique index (API)', kind: 'live', version: 'current ontology (unpinned)',
    upstream: 'https://d3fend.mitre.org/api/technique/all.json', licence: 'd3fend',
    inventoryRow: R.d3fendSeed, owner: 'services/d3fend.service.ts',
  },
  {
    id: 'd3fend-technique-api', name: 'D3FEND per-technique mappings (API)', kind: 'live', version: 'current ontology (unpinned)',
    upstream: 'https://d3fend.mitre.org/api/offensive-technique/attack/', licence: 'd3fend',
    inventoryRow: R.d3fendSeed, owner: 'services/d3fend.service.ts', onDemand: true,
  },
  {
    id: 'car-seed', name: 'CAR analytics seed', kind: 'seed', reviewedDate: '2026-08-15',
    upstream: 'https://github.com/mitre-attack/car', licence: 'car-apache-2.0',
    inventoryRow: R.curatedTables, owner: 'services/car.service.ts', initialStatus: 'loaded',
    note: 'Each id verified against mitre-attack/car on 2026-08-15.',
  },
  {
    id: 'wazuh-rules', name: 'Wazuh stock-rule table', kind: 'project-authored', reviewedDate: '2026-10-16',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.curatedTables,
    owner: 'services/wazuh.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'yara-templates', name: 'YARA templates', kind: 'project-authored', reviewedDate: '2026-10-16',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.curatedTables,
    owner: 'services/yara.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'zeek-templates', name: 'Zeek templates', kind: 'project-authored', reviewedDate: '2026-08-14',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.curatedTables,
    owner: 'services/zeek.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'suricata-templates', name: 'Suricata templates', kind: 'project-authored', reviewedDate: '2026-09-23',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.curatedTables,
    owner: 'services/suricata.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'event-logging', name: 'Event-logging guidance table', kind: 'project-authored', reviewedDate: '2026-10-16',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.curatedTables,
    owner: 'services/event-logging.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'ir-playbooks', name: 'IR playbooks', kind: 'project-authored', reviewedDate: '2026-10-16',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.curatedTables,
    owner: 'services/ir-playbook.service.ts', initialStatus: 'loaded',
  },
  {
    id: 'library-index', name: 'Library index (library.json)', kind: 'bundled', version: 'generated 2026-04-18T01:55:35Z',
    upstream: 'https://github.com/TeamStarWolf', licence: 'project-mit',
    inventoryRow: R.library, owner: 'services/library.service.ts',
    note: 'Copied by hand from the TeamStarWolf library builder.',
  },
  {
    id: 'library-layers', name: 'Library layers (index.json and layer files)', kind: 'bundled', reviewedDate: '2026-10-16',
    upstream: 'https://github.com/TeamStarWolf', licence: 'project-mit',
    inventoryRow: R.library, owner: 'services/library-layer.service.ts',
  },
  {
    id: 'lylat-mission-layers', name: 'Lylat mission layers', kind: 'project-authored', reviewedDate: '2026-10-16',
    upstream: 'no upstream', licence: 'project-mit', inventoryRow: R.lylat,
    owner: 'src/assets/data/lylat-mission-layers/',
    note: 'Shipped but loaded by no code path; E2.5 replaces them.',
  },
];
