// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Which SourceRecords each route reads (product plan 6.4, epic E1.3). The shared
// view banner (SourceBannerComponent) looks the current route up here and names
// every listed source that is 'failed' or 'empty' in the SourceRegistry.
//
// A route lists the sources its own panel reads. The matrix also lists the sources
// behind its lenses and behind the technique drawer it opens, because that drawer
// is how the matrix shows a technique's detail. Keys are router paths without the
// query string; route names do not change in Phase 1, so this table does not either.
import type { AttackDomain } from './data.service';

/** Stands for the active domain's ATT&CK bundles (bundled and live copy). */
export const ACTIVE_ATTACK = '@attack';

/** The ATT&CK SourceRecords behind each domain. */
export const ATTACK_SOURCES: Readonly<Record<AttackDomain, readonly string[]>> = {
  enterprise: ['attack-enterprise', 'attack-live-enterprise'],
  ics: ['attack-ics', 'attack-live-ics'],
  mobile: ['attack-mobile', 'attack-live-mobile'],
  f3: ['attack-f3', 'attack-live-f3'],
};

/** Lens sources: the reference, threat and library layers the matrix colours by. */
const MATRIX_LENS_SOURCES = [
  'library-layers',
  'atomic-layer',
  'car-layer',
  'sigmahq-coverage',
  'ctid-attack-to-cve',
  'ctid-kev',
  'cisa-kev',
  'ctid-nist-800-53',
  'ctid-cri-profile',
  'ctid-csa-ccm',
  'ctid-veris',
  'ctid-m365',
  'cve2capec-runtime',
  'd3fend-ontology',
  'elastic-tree',
  'splunk-tree',
  'engage',
  'm365-hunting-queries',
  'misp-galaxy',
  'trickest-poc-tree',
];

/** Technique-drawer sources: what the drawer opened from a matrix cell fetches. */
const TECHNIQUE_DRAWER_SOURCES = [
  'capec',
  'ctid-aws',
  'ctid-azure',
  'ctid-gcp',
  'atomic-tests',
  'd3fend-technique-api',
  'mdecrevoisier-sigma-tree',
  'nuclei-tree',
  'exploitdb',
  'cyb3r-monk-hunting-tree',
  'evtx-samples-tree',
  'payloads-tree',
  'ipsum',
  'threathunter-playbook',
  'anthropic-skills-layer',
  'library-index',
  'technique-queries',
];

export const ROUTE_SOURCES: Readonly<Record<string, readonly string[]>> = {
  '/matrix': [ACTIVE_ATTACK, ...MATRIX_LENS_SOURCES, ...TECHNIQUE_DRAWER_SOURCES],

  '/dashboard/overview': [
    'atomic-layer', 'sigmahq-coverage', 'ctid-attack-to-cve', 'ctid-kev', 'cisa-kev',
    'misp-galaxy', 'd3fend-ontology', 'car-layer', 'elastic-tree', 'splunk-tree',
  ],
  '/dashboard/analytics': ['cisa-kev', 'ctid-attack-to-cve', 'ctid-nist-800-53', 'sigmahq-coverage'],

  '/intel/groups': ['cisa-kev', 'ctid-attack-to-cve'],
  '/intel/scenarios': ['atomic-layer', 'car-layer', 'd3fend-ontology'],
  '/intel/emulation': ['library-index'],
  '/intel/feeds': ['misp-galaxy'],

  '/detect/detections': ['atomic-layer', 'car-layer', 'd3fend-ontology'],
  '/detect/sigma': ['sigmahq-coverage'],
  '/detect/siem': ['car-layer', 'technique-queries'],
  '/detect/validation': ['atomic-layer', 'sigmahq-coverage', 'library-index', 'technique-queries'],
  '/detect/purple-team': ['atomic-layer', 'atomic-tests', 'car-layer', 'd3fend-ontology', 'engage'],

  '/exposure/cve': [
    'nvd', 'cisa-kev', 'epss', 'cve-services', 'ctid-attack-to-cve', 'ctid-kev', 'capec',
    'cve2capec-runtime', 'cwe-catalog', 'cwe-exploitation-anchor', 'd3fend-ontology', 'trickest-poc-tree',
  ],
  '/exposure/graph': ['ctid-attack-to-cve', 'd3fend-ontology'],
  '/exposure/gap-analysis': ['library-index'],
  '/exposure/priority': ['atomic-layer', 'sigmahq-coverage', 'ctid-nist-800-53', 'ctid-attack-to-cve', 'cisa-kev', 'epss'],
  '/exposure/ssvc': ['ssvc-tables', 'cisa-kev', 'nvd', 'epss', 'ctid-attack-to-cve'],
  '/exposure/dossier': ['cve-dossiers', 'ssvc-tables', 'cve-services', 'cisa-kev', 'epss', 'attack-f3'],
  '/exposure/ctem': ['cve2capec-runtime', 'cisa-kev', 'nvd'],

  '/coverage/assessment': ['cisa-kev', 'ctid-attack-to-cve', 'epss'],
  '/coverage/compliance': [
    'ctid-nist-800-53', 'ctid-cri-profile', 'ctid-csa-ccm', 'ctid-aws', 'ctid-azure', 'ctid-gcp', 'ctid-m365', 'cis-controls',
  ],
  '/coverage/assets': ['ctid-attack-to-cve', 'cisa-kev'],

  '/library/workbench': ['library-index'],
  '/library/roadmap': ['ctid-attack-to-cve'],

  '/settings/changelog': ['attack-releases'],
};

/** The router path of a URL: no query string or fragment; the empty path is the matrix. */
export function routePath(url: string): string {
  const path = url.split('#')[0].split('?')[0].replace(/\/+$/, '');
  return path === '' ? '/matrix' : path;
}

/** The SourceRecord ids a route reads, with the active domain's ATT&CK sources resolved. */
export function sourcesForRoute(url: string, domain: AttackDomain): string[] {
  const listed = ROUTE_SOURCES[routePath(url)] ?? [];
  const ids = listed.flatMap(id => (id === ACTIVE_ATTACK ? [...ATTACK_SOURCES[domain]] : [id]));
  return [...new Set(ids)];
}
