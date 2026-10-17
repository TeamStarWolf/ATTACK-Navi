// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The section 6.3 source inventory of the product plan (ATTACK-Navi-Product-Plan,
// "Build-time pipeline and the source inventory"), checked in so a spec can compare
// the SourceRegistry against it. One entry per table row: `source` is the row's
// "Source" cell verbatim, `today` its "Today" cell in short. A row is either served
// by at least one SourceRecord or marked `absentToday` with the reason.
//
// Edit this list only when the plan's table changes; edit source-inventory.ts when
// the code changes.

export interface InventoryRow {
  source: string;
  today: string;
  /** The row names something the app does not ship or fetch today. */
  absentToday?: string;
}

export const SECTION_6_3_INVENTORY: readonly InventoryRow[] = [
  { source: 'ATT&CK Enterprise / ICS / Mobile / F3 bundles', today: 'bundled; live mode follows master' },
  { source: 'ATLAS', today: 'absent', absentToday: 'ATLAS is not loaded anywhere today; E3.5 adds it as a read-only domain.' },
  { source: 'cve-technique-map.json (CVE to CWE to CAPEC to ATT&CK)', today: 'bundled, built from unpinned Galeax/CVE2CAPEC@main' },
  { source: 'CVE2CAPEC runtime fetch', today: 'runtime, GPL-3.0' },
  { source: 'CTID attack_to_cve', today: 'runtime, archived 2024-04' },
  { source: 'CISA KEV', today: "runtime; double failure looked like 'loaded, 0' (#113)" },
  { source: 'EPSS, NVD', today: 'runtime; EPSS health hard-coded of(true)' },
  { source: 'CTID mappings (NIST 800-53, CRI, CSA CCM, VERIS, AWS, Azure, GCP, M365)', today: 'runtime, mapped vs ATT&CK 16.1 / 17.1' },
  { source: 'CIS Controls', today: 'loads empty; CTID removed the source' },
  { source: 'Sigma coverage, CAR, Atomic, CAPEC, MISP galaxy, Engage', today: 'runtime' },
  { source: 'Elastic, Splunk, Sentinel (edoardogerosa)', today: 'path regex over GitHub trees' },
  { source: 'M365 Defender hunting queries', today: 'archived 2022-02' },
  { source: 'trickest PoC tree', today: 'runtime tree' },
  { source: 'Nuclei templates', today: 'runtime tree' },
  { source: 'mdecrevoisier Sigma, Threat-Hunting', today: 'GitHub trees' },
  { source: 'EVTX samples', today: 'GitHub tree' },
  { source: 'PayloadsAllTheThings, ExploitDB, offensive tools', today: 'runtime trees and an in-code list' },
  { source: 'ipsum IP reputation list', today: 'runtime' },
  { source: 'ThreatHunter Playbook layer', today: 'ATT&CK v10, 13 techniques' },
  { source: 'mukul975 third-party layer', today: 'runtime on boot' },
  { source: 'cwe-catalog.json', today: '708 entries, no version, no refresh' },
  { source: 'cwe-exploitation-anchor.json', today: 'project-authored by hand' },
  { source: 'technique-queries.json', today: 'hand, 13 techniques' },
  { source: 'ssvc-decision-tables.json', today: 'manual script, generated 2026-09-24' },
  { source: 'CVE dossiers (22 files, newest CVE-2024-21893)', today: 'manual generator' },
  { source: 'D3FEND seed', today: 'in code, pruned against D3FEND 1.4.0' },
  { source: 'CAR seed, Wazuh stock-rule table (~22 ids), YARA, Zeek, Suricata, event-logging, IR playbooks', today: 'hand-maintained TypeScript' },
  { source: 'Library layers and library.json', today: 'manual copy' },
  { source: 'Lylat mission layers', today: '35 files, 0 code references' },
];

/**
 * Records each multi-source row must contain, so a row is not "covered" by one record
 * while another named source in it goes unregistered.
 */
export const REQUIRED_RECORDS_BY_ROW: Readonly<Record<string, readonly string[]>> = {
  'ATT&CK Enterprise / ICS / Mobile / F3 bundles': ['attack-enterprise', 'attack-ics', 'attack-mobile', 'attack-f3'],
  'EPSS, NVD': ['epss', 'nvd'],
  'CTID mappings (NIST 800-53, CRI, CSA CCM, VERIS, AWS, Azure, GCP, M365)': [
    'ctid-nist-800-53', 'ctid-cri-profile', 'ctid-csa-ccm', 'ctid-veris', 'ctid-aws', 'ctid-azure', 'ctid-gcp', 'ctid-m365',
  ],
  'Sigma coverage, CAR, Atomic, CAPEC, MISP galaxy, Engage': ['sigmahq-coverage', 'car-layer', 'atomic-layer', 'capec', 'misp-galaxy', 'engage'],
  'Elastic, Splunk, Sentinel (edoardogerosa)': ['elastic-tree', 'splunk-tree', 'sentinel-attack-tree'],
  'mdecrevoisier Sigma, Threat-Hunting': ['mdecrevoisier-sigma-tree', 'cyb3r-monk-hunting-tree'],
  'PayloadsAllTheThings, ExploitDB, offensive tools': ['payloads-tree', 'exploitdb', 'offensive-tools'],
  'CAR seed, Wazuh stock-rule table (~22 ids), YARA, Zeek, Suricata, event-logging, IR playbooks': [
    'car-seed', 'wazuh-rules', 'yara-templates', 'zeek-templates', 'suricata-templates', 'event-logging', 'ir-playbooks',
  ],
  'Library layers and library.json': ['library-layers', 'library-index'],
};
