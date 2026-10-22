// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { AttackDomain } from '../services/data.service';
import { LibraryLayerMeta } from '../services/library-layer.service';
import { Domain } from './domain';
import { ThreatGroup } from './group';
import { Technique } from './technique';
import type { ThreatProfileEmptyReason } from './posture/posture.types';

/** How a threat profile is defined. Every id is a STIX id (never a G#### attackId). */
export type ThreatProfileSource =
  | { kind: 'top-groups'; n: number }               // default n = 20, ranked by prevalence (design §10.4 item 1)
  | { kind: 'groups'; ids: readonly string[] }      // STIX intrusion-set ids
  | { kind: 'campaigns'; ids: readonly string[] }   // STIX campaign ids
  | { kind: 'library-layer'; file: string }         // library-layers manifest name; T#### resolved to STIX via domain
  | { kind: 'all' };

/**
 * Why a resolved profile holds no parent technique, or null when it holds some
 * (ThreatWeightProvider.emptyReason, RP-F item 6 round 1). Keyed on the stored
 * source, not on the parent count alone: an empty parent set also comes from a
 * profile that IS set, while a domain or a library layer loads, or when its
 * groups or campaigns use no technique in the loaded domain.
 */
export function threatProfileEmptyReason(
  src: ThreatProfileSource,
  parentCount: number,
  domainLoaded: boolean,
  layerLoaded: boolean,
): ThreatProfileEmptyReason | null {
  if (parentCount > 0) return null;
  if ((src.kind === 'groups' || src.kind === 'campaigns') && src.ids.length === 0) return 'names-nothing';
  if (!domainLoaded || (src.kind === 'library-layer' && !layerLoaded)) return 'resolving';
  return 'none-in-domain';
}

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
  /**
   * Group/campaign names using exactly this technique, no roll-up: the basis of the
   * evidence card's Threat block, which counts direct uses only, as its "Used by N
   * groups in the loaded ATT&CK bundle" line does (RP-F decision 28).
   */
  usedByDirect(techniqueStixId: string): readonly string[];
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

/**
 * A group named by a profile: its STIX id and the name to show (an absent group's name
 * is remembered, see ThreatProfileService). `unresolved` marks a stored id that names
 * no group seen this session (RP-F decision 18); its name is then the id as stored.
 */
export interface ProfileGroupRef { readonly id: string; readonly name: string; readonly unresolved?: boolean; }

/**
 * A stored groups profile split against one domain: the groups the domain carries
 * (present), the known groups it does not (absent), and the stored ids that resolve
 * to no group at all (unresolved: an alias, a revoked or unknown ATT&CK id, a
 * malformed STIX id; RP-F decision 18). The stored profile is never narrowed; the
 * split only says which of its groups this domain can resolve.
 */
export interface ProfileDomainGroups {
  readonly domain: AttackDomain;
  readonly present: readonly ProfileGroupRef[];
  readonly absent: readonly ProfileGroupRef[];
  /** Stored ids, as stored, that name no known group (RP-F decision 18); absent means none. */
  readonly unresolved?: readonly string[];
}

/**
 * A STIX intrusion-set id by its shape (the type prefix): the one shape a stored groups
 * profile keeps, and the only key a stored name hint may carry (RP-F decision 18). A
 * well-shaped id that names no group (an all-zero uuid) is caught by resolution, not here.
 */
export const STIX_GROUP_ID = /^intrusion-set--\S+$/;

/** What an unresolved stored id reads as, wherever the profile names it (RP-F decision 18). */
export const UNRESOLVED_GROUP_WORDS = 'unknown or withdrawn group id';

/** The short domain name the cross-domain notice uses ("present in ICS"). */
export const ATTACK_DOMAIN_SHORT_LABEL: Readonly<Record<AttackDomain, string>> = {
  enterprise: 'Enterprise',
  ics: 'ICS',
  mobile: 'Mobile',
  f3: 'F3',
};

/** A group as a stored profile id can name it: STIX id, ATT&CK id ('' when unknown) and name. */
export type KnownGroup = Pick<ThreatGroup, 'id' | 'attackId' | 'name'>;

/**
 * One group of the build-time group index, src/assets/data/group-index.json
 * (scripts/build-group-index.mjs; RP-F decision 25): every intrusion-set of the
 * bundled Enterprise, ICS and Mobile STIX files, with the domains that carry it as
 * a current group. The profile resolves stored ids against it, so a real group the
 * loaded domain lacks is named, on a fresh boot into any domain.
 */
export interface GroupIndexEntry {
  readonly attackId: string;
  readonly stixId: string;
  readonly name: string;
  readonly aliases: readonly string[];
  readonly revoked: boolean;
  readonly deprecated: boolean;
  readonly domains: readonly string[];
}

/**
 * The CURRENT groups of the index as KnownGroups (STIX id, ATT&CK id, name), for
 * indexGroups. A revoked or deprecated group is left out, so its ids stay
 * unresolved ("unknown or withdrawn"), as is a group with no ATT&CK id. Aliases are
 * never ids: "Fancy Bear" resolves to no group (RP-F decision 18).
 */
export function currentIndexedGroups(entries: readonly GroupIndexEntry[]): KnownGroup[] {
  return entries
    .filter((e) => !e.revoked && !e.deprecated && e.attackId !== '' && STIX_GROUP_ID.test(e.stixId) && e.name !== '')
    .map((e) => ({ id: e.stixId, attackId: e.attackId, name: e.name }));
}

/** Stored ids as the profile reads them: trimmed, empty ids dropped (" G0016 " is G0016; "" is nothing). */
export function cleanStoredIds(ids: readonly string[]): string[] {
  return ids.map((id) => id.trim()).filter((id) => id !== '');
}

/**
 * Groups keyed by every id a stored profile may hold them under: the STIX id as
 * is and the ATT&CK id upper-cased (RP-F decision 13). Built with indexGroups,
 * read with findStoredGroup; the one lookup behind both the membership rule
 * (splitStoredGroups) and the name of an absent group (ThreatProfileService).
 */
export type GroupIdIndex = ReadonlyMap<string, KnownGroup>;

/** Add `groups` to `index` under their STIX id and their upper-cased ATT&CK id. */
export function indexGroups(index: Map<string, KnownGroup>, groups: Iterable<KnownGroup>): void {
  for (const g of groups) {
    index.set(g.id, g);
    if (g.attackId) index.set(g.attackId.toUpperCase(), g);
  }
}

/** The group a stored id names in `index`: by STIX id, or by ATT&CK id in any case (G0016, g0016). */
export function findStoredGroup(index: GroupIdIndex, id: string): KnownGroup | undefined {
  return index.get(id) ?? index.get(id.toUpperCase());
}

/**
 * The real group a stored id names in `known`: by STIX id or by ATT&CK id in any
 * case, and only a group with an ATT&CK id (a group of a loaded domain or of the
 * group index). An entry with no ATT&CK id is a name hint, and a hint is never a
 * resolution (RP-F decision 25).
 */
export function resolveStoredGroup(known: GroupIdIndex, id: string): KnownGroup | undefined {
  const g = findStoredGroup(known, id);
  return g && g.attackId ? g : undefined;
}

/**
 * THE membership rule for a stored group list against a domain: a stored id is
 * present when the domain's groups carry it, by STIX id or by ATT&CK id (G0016,
 * any case: a profile stored with ATT&CK ids must not read "has no Enterprise
 * use" for a group that is there, RP-F decision 13), absent when it names a real
 * group the domain does not carry. resolveProfile and
 * ThreatProfileService.presentGroups/absentGroups both use this, so the profile
 * the surfaces count and the notice that names the absent groups never disagree.
 * `present` keeps the domain's order (the order resolveProfile has always used),
 * each group once even when stored under both ids. `absentIds` keeps the stored
 * order, each group once: `known` (the groups of every domain seen and of the
 * all-domain group index, RP-F decision 25) tells that a STIX id and an ATT&CK id
 * stored side by side are one group, which is then named once under the id
 * stored first. Stored ids are trimmed and empty ids dropped (cleanStoredIds).
 *
 * A stored id that resolves to no real group is `unresolvedIds`, never absent
 * (RP-F decisions 18 and 25): it is in neither the domain nor `known` as a group
 * with an ATT&CK id (an alias such as "Fancy Bear", a revoked G0057 or deprecated
 * G0014, an unknown G9999, a malformed or all-zero STIX id). A name hint never
 * resolves an id (resolveStoredGroup). Saying such an id "has no <domain> use"
 * would claim a group exists that does not.
 */
export function splitStoredGroups(
  ids: readonly string[],
  domain: Pick<Domain, 'groups'>,
  known: GroupIdIndex = new Map(),
): { readonly present: readonly ThreatGroup[]; readonly absentIds: readonly string[]; readonly unresolvedIds: readonly string[] } {
  const inDomain = new Map<string, KnownGroup>();
  indexGroups(inDomain, domain.groups);
  const presentIds = new Set<string>();
  const absentIds: string[] = [];
  const unresolvedIds: string[] = [];
  const keys = new Set<string>();
  for (const id of cleanStoredIds(ids)) {
    const here = findStoredGroup(inDomain, id);
    if (here) {
      presentIds.add(here.id);
      continue;
    }
    const real = resolveStoredGroup(known, id);
    const key = real ? `id:${real.id}` : `unresolved:${id}`;
    if (keys.has(key)) continue;
    keys.add(key);
    (real ? absentIds : unresolvedIds).push(id);
  }
  return { present: domain.groups.filter((g) => presentIds.has(g.id)), absentIds, unresolvedIds };
}

/**
 * Stored group ids in the one stored shape, STIX ids (RP-F decisions 18 and 25): an
 * id that names a real group (`known`: the groups of a loaded domain or of the
 * all-domain group index, by STIX id or by ATT&CK id in any case) becomes that
 * group's STIX id; any other id is kept as it is (an unresolved id is announced,
 * never dropped). Ids are trimmed and empty ids dropped; order is kept and each
 * group appears once.
 */
export function normaliseStoredGroupIds(ids: readonly string[], known: GroupIdIndex): string[] {
  const out: string[] = [];
  for (const id of cleanStoredIds(ids)) {
    const stix = resolveStoredGroup(known, id)?.id ?? id;
    if (!out.includes(stix)) out.push(stix);
  }
  return out;
}

/**
 * The name hint stored beside a groups profile (RP-F decision 25): the name of every
 * stored id that resolves to a real group, keyed by its STIX id. Built only from
 * resolved ids, so a hint never names an id that did not resolve. Keys are data:
 * the record has no prototype.
 */
export function groupNameHints(ids: readonly string[], known: GroupIdIndex): Record<string, string> {
  const names: Record<string, string> = Object.create(null);
  for (const id of cleanStoredIds(ids)) {
    const g = resolveStoredGroup(known, id);
    if (g && STIX_GROUP_ID.test(id)) names[id] = g.name;
  }
  return names;
}

/**
 * The one sentence every profile surface shows when some stored groups have no use
 * in the loaded domain, e.g. "1 of 2 groups present in ICS: FIN7; APT29 has no ICS
 * use". Null when nothing is absent or unresolved (the surfaces then show what they
 * always did). It names groups and domains only, and each stored id that resolves to
 * no group as "<id>: unknown or withdrawn group id" (RP-F decision 18): "1 of 2 groups
 * present in Enterprise: APT29; G9999: unknown or withdrawn group id".
 */
export function profileDomainNotice(split: ProfileDomainGroups | null): string | null {
  const unresolved = split?.unresolved ?? [];
  if (!split || (split.absent.length === 0 && unresolved.length === 0)) return null;
  const where = ATTACK_DOMAIN_SHORT_LABEL[split.domain] ?? split.domain;
  const total = split.present.length + split.absent.length + unresolved.length;
  const names = (refs: readonly ProfileGroupRef[]) => refs.map((r) => r.name).join(', ');
  const present = split.present.length > 0 ? `: ${names(split.present)}` : '';
  const parts = [`${split.present.length} of ${total} ${total === 1 ? 'group' : 'groups'} present in ${where}${present}`];
  if (split.absent.length > 0) parts.push(`${names(split.absent)} ${split.absent.length === 1 ? 'has' : 'have'} no ${where} use`);
  // RP-F decision 18: an id that resolves to no group is never "absent from" a domain.
  for (const id of unresolved) parts.push(`${id}: ${UNRESOLVED_GROUP_WORDS}`);
  return parts.join('; ');
}

const DOMAIN_NAME_TO_ATTACK: Readonly<Record<string, AttackDomain>> = {
  'Enterprise ATT&CK': 'enterprise',
  'ICS ATT&CK': 'ics',
  'Mobile ATT&CK': 'mobile',
  'F3 Fraud Framework': 'f3',
};

/** The AttackDomain a loaded Domain is (by its bundle name); 'enterprise' for an unknown name. */
export function attackDomainOf(domain: Pick<Domain, 'name'>): AttackDomain {
  return DOMAIN_NAME_TO_ATTACK[domain.name] ?? 'enterprise';
}

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
      const groups = splitStoredGroups(src.ids, domain).present;
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
  const direct = new Map<string, Set<string>>();
  for (const actor of actors) {
    for (const t of actor.techniques) {
      techniqueIds.add(t.id);
      const parent = parentOf(t.id);
      parentTechniqueIds.add(parent);
      (usage.get(parent) ?? usage.set(parent, new Set()).get(parent)!).add(actor.name);
      (direct.get(t.id) ?? direct.set(t.id, new Set()).get(t.id)!).add(actor.name);
    }
  }

  return {
    source: src,
    domain: attackDomainOf(domain),
    label,
    groupIds,
    techniqueIds,
    parentTechniqueIds,
    weight: (stix) => usage.get(parentOf(stix))?.size ?? 0,
    usedBy: (stix) => [...(usage.get(parentOf(stix)) ?? [])].sort(),
    usedByDirect: (stix) => [...(direct.get(stix) ?? [])].sort(),
  };
}
