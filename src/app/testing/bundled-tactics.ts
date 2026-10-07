// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Spec helper: the tactic vocabulary of every STIX bundle shipped under
// src/assets/data, read from the real files the app loads in bundled mode.
// Karma serves src/assets at /assets, so the bundles are fetched once per
// run and shared by every spec that imports this module.

export interface BundledTactic {
  shortname: string;
  name: string;
  attackId: string;
}

export interface BundledDomainTactics {
  /** Short key: enterprise | ics | mobile | f3. */
  key: string;
  file: string;
  /** x_mitre_version of the bundle's x-mitre-collection object. */
  version: string;
  /** Tactic shortnames in `x-mitre-matrix.tactic_refs` order (all matrices concatenated). */
  matrixOrder: string[];
  tactics: BundledTactic[];
  /** Every kill_chain_phase name carried by a live (not revoked/deprecated) attack-pattern. */
  livePhaseNames: string[];
  /** The parsed STIX bundle, for specs that need to run DataService over it. */
  raw: { objects: any[] };
}

export const BUNDLED_DOMAINS: ReadonlyArray<{ key: string; file: string }> = [
  { key: 'enterprise', file: 'assets/data/enterprise-attack.json' },
  { key: 'ics', file: 'assets/data/ics-attack.json' },
  { key: 'mobile', file: 'assets/data/mobile-attack.json' },
  { key: 'f3', file: 'assets/data/f3-attack.json' },
];

let cache: Promise<BundledDomainTactics[]> | null = null;

function extractAttackId(obj: any): string {
  for (const ref of obj.external_references ?? []) {
    if (typeof ref?.source_name === 'string' && ref.source_name.startsWith('mitre-') && ref.external_id) {
      return String(ref.external_id);
    }
  }
  return '';
}

function summarize(key: string, file: string, raw: { objects: any[] }): BundledDomainTactics {
  const objects = raw.objects ?? [];
  const byId = new Map<string, any>();
  const tactics: BundledTactic[] = [];
  let version = '';
  const livePhases = new Set<string>();

  for (const o of objects) {
    if (o.type === 'x-mitre-collection') version = String(o.x_mitre_version ?? '');
    if (o.type === 'x-mitre-tactic') {
      byId.set(o.id, o);
      tactics.push({ shortname: String(o.x_mitre_shortname ?? ''), name: String(o.name ?? ''), attackId: extractAttackId(o) });
    }
    if (o.type === 'attack-pattern' && !o.revoked && !o.x_mitre_deprecated) {
      for (const k of o.kill_chain_phases ?? []) livePhases.add(String(k.phase_name));
    }
  }

  const matrixOrder: string[] = [];
  for (const o of objects) {
    if (o.type !== 'x-mitre-matrix') continue;
    for (const ref of o.tactic_refs ?? []) {
      const t = byId.get(ref);
      if (t?.x_mitre_shortname && !matrixOrder.includes(t.x_mitre_shortname)) matrixOrder.push(t.x_mitre_shortname);
    }
  }

  return { key, file, version, matrixOrder, tactics, livePhaseNames: [...livePhases].sort(), raw };
}

/** Loads (once) and summarizes every bundled domain. */
export function loadBundledTactics(): Promise<BundledDomainTactics[]> {
  if (!cache) {
    cache = Promise.all(
      BUNDLED_DOMAINS.map(async ({ key, file }) => {
        const res = await fetch(file);
        if (!res.ok) throw new Error(`${file}: HTTP ${res.status}`);
        const raw = (await res.json()) as { objects: any[] };
        return summarize(key, file, raw);
      }),
    );
  }
  return cache;
}
