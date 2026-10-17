// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// What each compliance tab's mapping is, and which ATT&CK release it was mapped
// against (plan epic E1.6, section 6.3 "CTID mappings ... mapped vs ATT&CK 16.1 /
// 17.1" and "CIS Controls ... 'source withdrawn upstream' row; removed from
// scores"). The stamps are read from the source inventory, the one place the
// bundled mapping metadata lives, so a tab can never claim a version its loader
// does not fetch.
import { SourceDefinition } from '../../models/source-record';
import { BUNDLED_ATTACK_VERSION, SOURCE_DEFINITIONS } from '../../services/source-inventory';

/** The compliance panel's tabs, in the order the tab bar shows them. */
export const COMPLIANCE_TABS = ['cis', 'aws', 'azure', 'gcp', 'nist', 'cri', 'csa-ccm', 'm365-ctrl', 'soc2', 'iso27001', 'pci'] as const;
export type ComplianceTab = typeof COMPLIANCE_TABS[number];

/** The source each tab's controls come from (an id in SOURCE_DEFINITIONS). */
export const COMPLIANCE_TAB_SOURCE: Readonly<Record<ComplianceTab, string>> = {
  'cis': 'cis-controls',
  'aws': 'ctid-aws',
  'azure': 'ctid-azure',
  'gcp': 'ctid-gcp',
  'nist': 'ctid-nist-800-53',
  'cri': 'ctid-cri-profile',
  'csa-ccm': 'ctid-csa-ccm',
  'm365-ctrl': 'ctid-m365',
  'soc2': 'compliance-mapper-seed',
  'iso27001': 'compliance-mapper-seed',
  'pci': 'compliance-mapper-seed',
};

export interface ComplianceTabMeta {
  tab: ComplianceTab;
  sourceId: string;
  /** The ATT&CK release the mapping was made against ('16.1'), or null when it names none. */
  mappedVs: string | null;
  /** The upstream withdrew the mapping: nothing loads and the tab is left out of the scores. */
  withdrawn: boolean;
  /** One line every tab shows: what the mapping is and which ATT&CK release it was mapped against. */
  stamp: string;
}

const MAPPED_VS = /mapped vs ATT&CK (\d+(?:\.\d+)*)/;

/** The ATT&CK release a source definition says its mapping was made against, or null. */
export function mappedVsAttack(def: Pick<SourceDefinition, 'version'>): string | null {
  return def.version?.match(MAPPED_VS)?.[1] ?? null;
}

function metaFor(tab: ComplianceTab): ComplianceTabMeta {
  const sourceId = COMPLIANCE_TAB_SOURCE[tab];
  const def = SOURCE_DEFINITIONS.find(d => d.id === sourceId);
  if (!def) throw new Error(`compliance tab '${tab}': no source definition '${sourceId}'`);
  const mappedVs = mappedVsAttack(def);
  const withdrawn = def.initialStatus === 'archived-upstream' && mappedVs === null;
  let stamp: string;
  if (withdrawn) {
    stamp = 'Source withdrawn upstream: CTID removed the CIS Controls mapping from Mappings Explorer as of ATT&CK 16, '
      + 'so nothing is loaded and CIS is left out of the scores.';
  } else if (mappedVs !== null) {
    stamp = `CTID mapping ${def.version} (the matrix shows ATT&CK ${BUNDLED_ATTACK_VERSION}).`;
  } else if (def.kind === 'project-authored') {
    stamp = `Project-authored mapping, reviewed ${def.reviewedDate}, not mapped against a specific ATT&CK release.`;
  } else {
    stamp = `Mapping ${def.version ?? 'version not recorded'}.`;
  }
  return { tab, sourceId, mappedVs, withdrawn, stamp };
}

/** The mapping metadata of every compliance tab. */
export const COMPLIANCE_TAB_META: Readonly<Record<ComplianceTab, ComplianceTabMeta>> =
  Object.fromEntries(COMPLIANCE_TABS.map(tab => [tab, metaFor(tab)])) as Record<ComplianceTab, ComplianceTabMeta>;
