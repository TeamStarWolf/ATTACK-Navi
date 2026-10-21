// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Two pure tests over one technique's signal families (Phase 2 design §3 P2-08,
// E2.1-d2). They replace EnrichmentService.hasDefensiveSignal and isEnriched,
// both deleted in P2-08, with identical results: every caller passes
// EnrichmentService.signals(tech, domain) and gets the answer the method gave.
//
// Callers (P2-08): the matrix "Dim uncovered" test, the dashboard
// criticalRisk and kevExposedGap counters, and EnrichmentService.riskScore.
// Making those three read posture is P2-09's change, not this file's.

/**
 * The seven signal families of one technique, as EnrichmentService.signals()
 * returns them. Five are defensive reference inputs (mitigation, detection,
 * atomic, d3fend, control); threatIntel and cve describe adversary interest.
 */
export interface SignalFamilies {
  readonly mitigation: boolean;
  readonly detection: boolean;
  readonly atomic: boolean;
  readonly d3fend: boolean;
  readonly control: boolean;
  readonly threatIntel: boolean;
  readonly cve: boolean;
}

/**
 * A defensive reference input other than an Atomic test: a mapped mitigation,
 * detection content, a control-framework mapping or a D3FEND countermeasure
 * (the deleted hasDefensiveSignal). Narrower than Known 'mapped'
 * (EnrichmentService.isReferenceMapped), which also counts Atomic tests.
 * Threat-intel and CVE links never count.
 */
export function hasDefensiveReference(s: SignalFamilies): boolean {
  return s.mitigation || s.detection || s.control || s.d3fend;
}

/**
 * Any of the seven families, threat-intel links and CVE mappings included (the
 * deleted isEnriched). Threat side: it rises when a group starts using a
 * technique, so it never feeds a Known 'mapped' count.
 */
export function hasAnySignal(s: SignalFamilies): boolean {
  return s.mitigation || s.detection || s.atomic || s.d3fend || s.control || s.threatIntel || s.cve;
}
