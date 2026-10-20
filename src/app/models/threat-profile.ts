// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { AttackDomain } from '../services/data.service';
import { LibraryLayerMeta } from '../services/library-layer.service';
import { Domain } from './domain';
import { ThreatGroup } from './group';
import { Technique } from './technique';

/** How a threat profile is defined. Every id is a STIX id (never a G#### attackId). */
export type ThreatProfileSource =
  | { kind: 'top-groups'; n: number }               // default n = 20, ranked by prevalence (design §10.4 item 1)
  | { kind: 'groups'; ids: readonly string[] }      // STIX intrusion-set ids
  | { kind: 'campaigns'; ids: readonly string[] }   // STIX campaign ids
  | { kind: 'library-layer'; file: string }         // library-layers manifest name; T#### resolved to STIX via domain
  | { kind: 'all' };

export interface ThreatProfile {
  readonly source: ThreatProfileSource;
  readonly domain: AttackDomain;
  readonly label: string;                            // 'Top 20 groups by prevalence'
  // STIX intrusion-set ids: the selected/top groups; every group for 'all'; the
  // campaigns' attributed groups for 'campaigns'; empty for 'library-layer'.
  readonly groupIds: readonly string[];
  readonly techniqueIds: ReadonlySet<string>;        // STIX, parents and subs
  readonly parentTechniqueIds: ReadonlySet<string>;  // subs rolled up to parents: THE denominator
  /** threatWeight = profile actors using the technique; sub usage rolls up to the parent. */
  weight(techniqueStixId: string): number;
  /** Group/campaign names using the technique (sub usage rolls up to the parent). */
  usedBy(techniqueStixId: string): readonly string[];
}

/**
 * A library layer resolved from the manifest plus its file. No `LibraryLayer` type
 * exists; the manifest entry is LibraryLayerMeta (library-layer.service.ts:9) and
 * the layer file's shape is private to that service, so P2-03 defines this.
 */
export interface LibraryLayerInput {
  readonly meta: LibraryLayerMeta;
  readonly techniques: readonly { readonly techniqueID: string }[];
}

const DOMAIN_NAME_TO_ATTACK: Readonly<Record<string, AttackDomain>> = {
  'Enterprise ATT&CK': 'enterprise',
  'ICS ATT&CK': 'ics',
  'Mobile ATT&CK': 'mobile',
  'F3 Fraud Framework': 'f3',
};

/** Rank by Σ groupsByTechnique(t).length over the group's techniques; ties: campaign count, then attackId (Option A). */
export function rankGroupsByPrevalence(domain: Domain): readonly ThreatGroup[] {
  const prevalence = new Map<string, number>();
  for (const g of domain.groups) {
    let sum = 0;
    for (const t of domain.techniquesByGroup.get(g.id) ?? []) {
      sum += domain.groupsByTechnique.get(t.id)?.length ?? 0;
    }
    prevalence.set(g.id, sum);
  }
  return [...domain.groups].sort((a, b) => {
    const byPrevalence = (prevalence.get(b.id) ?? 0) - (prevalence.get(a.id) ?? 0);
    if (byPrevalence) return byPrevalence;
    const byCampaigns = (domain.campaignsByGroup.get(b.id)?.length ?? 0) - (domain.campaignsByGroup.get(a.id)?.length ?? 0);
    if (byCampaigns) return byCampaigns;
    return a.attackId.localeCompare(b.attackId);
  });
}

interface Actor { readonly name: string; readonly techniques: readonly Technique[]; }

/** Top-N is clamped to an integer in [1, number of groups]; a null/NaN/float n never reaches the label or the slice. */
function clampTopN(n: number, groupCount: number): number {
  const i = Number.isFinite(n) ? Math.trunc(n) : 0;
  return Math.min(Math.max(i, 1), Math.max(1, groupCount));
}

export function resolveProfile(src: ThreatProfileSource, domain: Domain, layer?: LibraryLayerInput): ThreatProfile {
  const byStix = new Map(domain.techniques.map((t) => [t.id, t]));
  const byAttackId = new Map(domain.techniques.map((t) => [t.attackId, t]));
  const parentOf = (stix: string): string => {
    const t = byStix.get(stix);
    return t && t.isSubtechnique && t.parentId ? t.parentId : stix;
  };

  let label: string;
  let groupIds: readonly string[] = [];
  const actors: Actor[] = [];
  const techniqueIds = new Set<string>();
  const parentTechniqueIds = new Set<string>();

  switch (src.kind) {
    case 'top-groups': {
      const n = clampTopN(src.n, domain.groups.length);
      const groups = rankGroupsByPrevalence(domain).slice(0, n);
      groupIds = groups.map((g) => g.id);
      label = `Top ${n} groups by prevalence`;
      for (const g of groups) actors.push({ name: g.name, techniques: domain.techniquesByGroup.get(g.id) ?? [] });
      break;
    }
    case 'groups': {
      const wanted = new Set(src.ids);
      const groups = domain.groups.filter((g) => wanted.has(g.id));
      groupIds = groups.map((g) => g.id);
      label = groups.length === 1 ? groups[0].name : `${groups.length} groups`;
      for (const g of groups) actors.push({ name: g.name, techniques: domain.techniquesByGroup.get(g.id) ?? [] });
      break;
    }
    case 'campaigns': {
      const wanted = new Set(src.ids);
      const campaigns = domain.campaigns.filter((c) => wanted.has(c.id));
      groupIds = [...new Set(campaigns.flatMap((c) => c.attributedGroupIds))];   // the intrusion-sets attributed to these campaigns
      label = campaigns.length === 1 ? campaigns[0].name : `${campaigns.length} campaigns`;
      for (const c of campaigns) actors.push({ name: c.name, techniques: domain.techniquesByCampaign.get(c.id) ?? [] });
      break;
    }
    case 'library-layer': {
      label = layer?.meta.name ?? src.file;
      const resolved: Technique[] = [];
      for (const entry of layer?.techniques ?? []) {
        const t = byAttackId.get(entry.techniqueID);
        if (t) resolved.push(t);
      }
      actors.push({ name: label, techniques: resolved });
      break;
    }
    case 'all': {
      label = 'All techniques';
      groupIds = domain.groups.map((g) => g.id);
      // Weight/usedBy over every group; the denominator is every parent technique.
      for (const g of domain.groups) actors.push({ name: g.name, techniques: domain.techniquesByGroup.get(g.id) ?? [] });
      for (const t of domain.techniques) {
        techniqueIds.add(t.id);
        parentTechniqueIds.add(parentOf(t.id));
      }
      break;
    }
  }

  const usage = new Map<string, Set<string>>();
  for (const actor of actors) {
    for (const t of actor.techniques) {
      techniqueIds.add(t.id);
      const parent = parentOf(t.id);
      parentTechniqueIds.add(parent);
      (usage.get(parent) ?? usage.set(parent, new Set()).get(parent)!).add(actor.name);
    }
  }

  return {
    source: src,
    domain: DOMAIN_NAME_TO_ATTACK[domain.name] ?? 'enterprise',
    label,
    groupIds,
    techniqueIds,
    parentTechniqueIds,
    weight: (stix) => usage.get(parentOf(stix))?.size ?? 0,
    usedBy: (stix) => [...(usage.get(parentOf(stix)) ?? [])].sort(),
  };
}
