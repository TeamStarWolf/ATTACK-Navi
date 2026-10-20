// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// TechniqueRef (Phase 2 design §2.1, §8): the one key new stores, PostureService
// and lens projections use for a technique. A ref names the framework, the
// domain, the id and the bundle version it was written under, serialised as
// 'attack/enterprise/T1059.001@19.2' (plan:508).
//
// Type-only imports: this file has no runtime dependency.
import type { AttackDomain } from '../services/data.service';
import type { Technique } from './technique';

export type RefFramework = 'attack' | 'atlas' | 'f3';

/** 'enterprise' | 'ics' | 'mobile' | 'f3' are AttackDomain (data.service.ts); 'atlas' is reserved for E9.4. */
export type RefDomain = AttackDomain | 'atlas';

export interface TechniqueRef {
  readonly framework: RefFramework;
  readonly domain: RefDomain;
  /** 'T1059.001', 'AML.T0051', 'F1001' (or a mitigation id, see MitigationRefKey). */
  readonly id: string;
  /** The loaded bundle's x_mitre_version (Domain.attackVersion). */
  readonly version: string;
}

/** 'attack/enterprise/T1059.001@19.2' (plan:508). */
export type TechniqueRefKey = `${RefFramework}/${RefDomain}/${string}@${string}`;

/** Mitigation refs share the serialisation: 'attack/enterprise/M1036@19.2'. */
export type MitigationRefKey = TechniqueRefKey;

/** The domains each framework may name. */
const DOMAINS: Readonly<Record<RefFramework, readonly RefDomain[]>> = {
  attack: ['enterprise', 'ics', 'mobile'],
  f3: ['f3'],
  atlas: ['atlas'],
};

/** Technique or mitigation ids each framework may carry. */
const IDS: Readonly<Record<RefFramework, RegExp>> = {
  attack: /^(?:T\d{4}(?:\.\d{3})?|M\d{4})$/,
  f3: /^(?:[TF]\d{4}(?:\.\d{3})?|M\d{4})$/,
  atlas: /^AML\.(?:T\d{4}(?:\.\d{3})?|M\d{4})$/,
};

/** A dotted numeric version: '19.2', '1.2', '5'. */
const VERSION = /^\d+(?:\.\d+)*$/;

const KEY = /^([a-z0-9]+)\/([a-z0-9]+)\/([^/@\s]+)@([^/@\s]+)$/;

export function techniqueRefKey(ref: TechniqueRef): TechniqueRefKey {
  return `${ref.framework}/${ref.domain}/${ref.id}@${ref.version}`;
}

function isFramework(s: string): s is RefFramework {
  return Object.prototype.hasOwnProperty.call(DOMAINS, s);
}

/**
 * Strict parser: null when any part is malformed (unknown framework, a domain
 * the framework does not have, an id that is not that framework's shape, or a
 * version that is not dotted digits).
 */
export function parseTechniqueRef(key: string): TechniqueRef | null {
  const m = KEY.exec(key);
  if (!m) return null;
  const [, framework, domain, id, version] = m;
  if (!isFramework(framework)) return null;
  if (!(DOMAINS[framework] as readonly string[]).includes(domain)) return null;
  if (!IDS[framework].test(id) || !VERSION.test(version)) return null;
  return { framework, domain: domain as RefDomain, id, version };
}

/** The ref of a technique in a loaded domain. An F3 technique gets framework 'f3'. */
export function refForTechnique(t: Pick<Technique, 'attackId'>, domain: AttackDomain, version: string): TechniqueRef {
  return { framework: domain === 'f3' ? 'f3' : 'attack', domain, id: t.attackId, version };
}

/**
 * F3 reuses Enterprise technique ids (§1.12): an f3 ref whose id is a T-id is
 * the attack/enterprise technique with that id. F-ids stay f3-only.
 */
function canonical(ref: TechniqueRef): { framework: RefFramework; domain: RefDomain } {
  if (ref.framework === 'f3' && ref.id.startsWith('T')) return { framework: 'attack', domain: 'enterprise' };
  return { framework: ref.framework, domain: ref.domain };
}

/**
 * Same technique, ignoring version (a version mismatch means resolve and remap,
 * never drop; R6 §3). F3 equivalence (§1.12): an f3 ref whose id is a T-id
 * equals the attack/enterprise ref with the same resolved id. F-ids are
 * f3-only. ICS and Mobile ids never equal Enterprise ids.
 */
export function sameTechnique(a: TechniqueRef, b: TechniqueRef, resolve: (id: string) => string): boolean {
  const ca = canonical(a);
  const cb = canonical(b);
  if (ca.framework !== cb.framework || ca.domain !== cb.domain) return false;
  return resolve(a.id) === resolve(b.id);
}
