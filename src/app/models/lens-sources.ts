// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The sources a heatmap lens reads, keyed by a stable id. Each id names one
// row of the source inventory in the product plan (section 6.3), except the
// two stated non-inventory ids: 'project-authored' (hand-written in this
// repository, no upstream) and 'workspace-local' (what the user entered in
// this browser).
//
// SEAM(E1.3): this static table and lensSourceVintage() stand in for E1.3's
// SourceRegistry / SourceRecord. When the registry lands, the legend should ask
// it for each id's pinned version, reviewed date and status instead; the ids
// below are the keys to carry over. Until then the vintage is what the code
// can state today: the bundled ATT&CK release read from the loaded bundle's
// x-mitre-collection (Domain.attackVersion), and the versions pinned in each
// loader's URL or seed comment.
import type { AttackDomain } from '../services/data.service';

export type LensSourceId =
  | 'attack-bundle'
  | 'cisa-kev'
  | 'ctid-kev'
  | 'cwe-exploitation-anchor'
  | 'ctid-attack-to-cve'
  | 'epss'
  | 'cve2capec'
  | 'trickest-poc'
  | 'sigmahq'
  | 'car'
  | 'car-seed'
  | 'atomic'
  | 'engage'
  | 'misp-galaxy'
  | 'elastic'
  | 'splunk'
  | 'm365-hunting'
  | 'wazuh-stock-rules'
  | 'd3fend-seed'
  | 'ctid-nist-800-53'
  | 'ctid-veris'
  | 'ctid-cri'
  | 'ctid-csa-ccm'
  | 'ctid-m365'
  | 'cis-controls'
  | 'library-layers'
  | 'project-authored'
  | 'workspace-local';

export type LensSourceDelivery = 'bundled' | 'runtime' | 'in-code' | 'local';

export interface LensSourceInfo {
  /** Display name for the legend's source line. */
  name: string;
  /** The section 6.3 inventory row this id belongs to, or null for the two stated non-inventory ids. */
  inventoryRow: string | null;
  delivery: LensSourceDelivery;
  /**
   * What the code pins today: a release, a dated snapshot or a review note.
   * null means nothing is pinned (the loader follows an upstream branch head).
   */
  pinned: string | null;
  /** The ATT&CK release the source's technique ids were mapped against, when known. */
  mappedVs?: string;
  /** Upstream state worth stating, e.g. archived. */
  note?: string;
}

const ROW_ATTACK = 'ATT&CK Enterprise / ICS / Mobile / F3 bundles';
const ROW_CTID = 'CTID mappings (NIST 800-53, CRI, CSA CCM, VERIS, AWS, Azure, GCP, M365)';
const ROW_CONTENT = 'Sigma coverage, CAR, Atomic, CAPEC, MISP galaxy, Engage';
const ROW_VENDOR = 'Elastic, Splunk, Sentinel (edoardogerosa)';
const ROW_CURATED = 'CAR seed, Wazuh stock-rule table (~22 ids), YARA, Zeek, Suricata, event-logging, IR playbooks';

export const LENS_SOURCES: Readonly<Record<LensSourceId, LensSourceInfo>> = {
  'attack-bundle': { name: 'ATT&CK bundle', inventoryRow: ROW_ATTACK, delivery: 'bundled', pinned: null },
  'cisa-kev': { name: 'CISA KEV', inventoryRow: 'CISA KEV', delivery: 'runtime', pinned: null },
  'ctid-kev': { name: 'CTID KEV mappings', inventoryRow: ROW_CTID, delivery: 'runtime', pinned: 'kev-07.28.2025', mappedVs: '16.1' },
  'cwe-exploitation-anchor': { name: 'CWE exploitation anchors', inventoryRow: 'cwe-exploitation-anchor.json', delivery: 'bundled', pinned: 'project-authored, no upstream' },
  'ctid-attack-to-cve': { name: 'CTID attack_to_cve', inventoryRow: 'CTID attack_to_cve', delivery: 'runtime', pinned: null, note: 'archived upstream 2024-04' },
  'epss': { name: 'FIRST EPSS', inventoryRow: 'EPSS, NVD', delivery: 'runtime', pinned: null, note: 'live per CVE' },
  'cve2capec': { name: 'CVE2CAPEC', inventoryRow: 'CVE2CAPEC runtime fetch', delivery: 'runtime', pinned: null },
  'trickest-poc': { name: 'trickest PoC index', inventoryRow: 'trickest PoC tree', delivery: 'runtime', pinned: null },
  'sigmahq': { name: 'SigmaHQ coverage', inventoryRow: ROW_CONTENT, delivery: 'runtime', pinned: null },
  'car': { name: 'MITRE CAR layer', inventoryRow: ROW_CONTENT, delivery: 'runtime', pinned: null, mappedVs: '14' },
  'car-seed': { name: 'CAR seed', inventoryRow: ROW_CURATED, delivery: 'in-code', pinned: 'curated in code, not refreshed' },
  'atomic': { name: 'Atomic Red Team', inventoryRow: ROW_CONTENT, delivery: 'runtime', pinned: null },
  'engage': { name: 'MITRE Engage', inventoryRow: ROW_CONTENT, delivery: 'runtime', pinned: null, note: 'archived upstream 2024-04' },
  'misp-galaxy': { name: 'MISP galaxy', inventoryRow: ROW_CONTENT, delivery: 'runtime', pinned: null },
  'elastic': { name: 'Elastic detection-rules', inventoryRow: ROW_VENDOR, delivery: 'runtime', pinned: null },
  'splunk': { name: 'Splunk security_content', inventoryRow: ROW_VENDOR, delivery: 'runtime', pinned: null },
  'm365-hunting': { name: 'M365 Defender hunting queries', inventoryRow: 'M365 Defender hunting queries', delivery: 'runtime', pinned: null, note: 'archived upstream 2022-02' },
  'wazuh-stock-rules': { name: 'Wazuh stock-rule table', inventoryRow: ROW_CURATED, delivery: 'in-code', pinned: 'curated in code', mappedVs: '19.2' },
  'd3fend-seed': { name: 'D3FEND seed', inventoryRow: 'D3FEND seed', delivery: 'in-code', pinned: 'pruned vs D3FEND 1.4.0', mappedVs: '19.2' },
  'ctid-nist-800-53': { name: 'CTID NIST 800-53', inventoryRow: ROW_CTID, delivery: 'runtime', pinned: 'rev5', mappedVs: '16.1' },
  'ctid-veris': { name: 'CTID VERIS', inventoryRow: ROW_CTID, delivery: 'runtime', pinned: '1.4.0', mappedVs: '16.1' },
  'ctid-cri': { name: 'CTID CRI Profile', inventoryRow: ROW_CTID, delivery: 'runtime', pinned: 'v2.1', mappedVs: '16.1' },
  'ctid-csa-ccm': { name: 'CTID CSA CCM', inventoryRow: ROW_CTID, delivery: 'runtime', pinned: '4.1', mappedVs: '17.1' },
  'ctid-m365': { name: 'CTID M365', inventoryRow: ROW_CTID, delivery: 'runtime', pinned: '07.18.2025', mappedVs: '16.1' },
  'cis-controls': { name: 'CIS Controls', inventoryRow: 'CIS Controls', delivery: 'runtime', pinned: null, note: 'loads empty: source withdrawn upstream' },
  'library-layers': { name: 'TeamStarWolf library layers', inventoryRow: 'Library layers and library.json', delivery: 'bundled', pinned: 'manual copy, no pinned commit' },
  'project-authored': { name: 'Project-authored heuristics', inventoryRow: null, delivery: 'in-code', pinned: 'hand-written in this repository, no upstream' },
  'workspace-local': { name: 'Your workspace', inventoryRow: null, delivery: 'local', pinned: 'entered in this browser' },
};

const DOMAIN_LABEL: Readonly<Record<AttackDomain, string>> = {
  enterprise: 'Enterprise ATT&CK',
  ics: 'ICS ATT&CK',
  mobile: 'Mobile ATT&CK',
  f3: 'CTID F3',
};

export function domainLabel(domain: AttackDomain): string {
  return DOMAIN_LABEL[domain];
}

/** What the running app knows about the loaded ATT&CK bundle. */
export interface LoadedBundleInfo {
  domain: AttackDomain;
  /** x_mitre_version of the loaded bundle's collection, '' when unknown or not loaded yet. */
  attackVersion: string;
  /** Where the loaded bundle came from (DataService.freshness$). */
  freshness: 'bundled' | 'cached' | 'live' | null;
}

/**
 * One source's vintage as the legend states it: its name, then the pinned
 * version or review note, the ATT&CK release it was mapped against, and any
 * upstream caveat. An unpinned runtime source says so instead of inventing a
 * version.
 *
 * SEAM(E1.3): replace the body with a SourceRegistry lookup.
 */
export function lensSourceVintage(id: LensSourceId, bundle: LoadedBundleInfo): string {
  const info = LENS_SOURCES[id];
  if (id === 'attack-bundle') {
    const version = bundle.attackVersion ? ` ${bundle.attackVersion}` : '';
    const from = bundle.freshness ? ` (${bundle.freshness})` : '';
    return `${domainLabel(bundle.domain)}${version}${from}`;
  }
  const parts: string[] = [];
  if (info.pinned) parts.push(info.pinned);
  else if (info.delivery === 'runtime') parts.push('fetched at runtime, unpinned');
  if (info.mappedVs) parts.push(`mapped vs ATT&CK ${info.mappedVs}`);
  if (info.note) parts.push(info.note);
  return parts.length ? `${info.name} (${parts.join('; ')})` : info.name;
}
