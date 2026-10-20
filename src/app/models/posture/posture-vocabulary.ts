// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The display vocabulary of the posture rungs (Phase 2 design §2.4, plan 4.1).
// Every Proven word any Phase 2 surface renders is composed from PROVEN, so the
// truth-vocabulary lint carries exactly one allow for it. Every Covered string
// names its qualifier right after the word (covered-unqualified,
// scripts/lint-truth-vocab.mjs), which is why the Covered strings below are
// whole literals rather than templates.
import type { CoveredQualifier } from '../heatmap-modes';
import type { CoveredMark, PostureState, ProofRecord, ProofScope } from './posture.types';

// truth-vocab-allow-next-line proven-only -- the Proven-rung word; every caller passes Proven-rung data
export const PROVEN = 'Proven';

const SCOPE_WORDS: Readonly<Record<ProofScope, string>> = {
  production: ' in production',
  range: ' in range',
  'own-run': ' (your run)',
};

/** The Covered head for a qualifier set, open so the partial form can continue it. */
function coveredHead(qualifiers: readonly CoveredQualifier[]): string {
  const self = qualifiers.includes('self-attested');
  const range = qualifiers.includes('range');
  if (self && range) return 'Covered (self-attested, range';
  if (range) return 'Covered (range';
  return 'Covered (self-attested';
}

/** The distinct `via` of the partial marks, in mark order. */
function partialVia(marks: readonly CoveredMark[]): string[] {
  const out: string[] = [];
  for (const m of marks) {
    if (m.strength === 'partial' && m.via && !out.includes(m.via)) out.push(m.via);
  }
  return out;
}

/**
 * The badge for one technique's posture:
 *   'Proven in range' | 'Proven in production' | 'Proven (your run)' | 'Proven in range (stale)'
 *   'Covered (self-attested)' | 'Covered (range)' | 'Covered (self-attested, range)'
 *   'Covered (self-attested, partial via M1038)'   (D16; passes covered-unqualified)
 *   'Known: mapped' | 'None'
 */
export function postureBadge(s: Pick<PostureState, 'bucket' | 'qualifiers' | 'proofScope' | 'covered'>): string {
  switch (s.bucket) {
    case 'proven':
    case 'stale': {
      const scope = s.proofScope ? SCOPE_WORDS[s.proofScope] : '';
      return PROVEN + scope + (s.bucket === 'stale' ? ' (stale)' : '');
    }
    case 'covered':
      return coveredHead(s.qualifiers) + ')';
    case 'partial': {
      const via = partialVia(s.covered);
      return coveredHead(s.qualifiers) + (via.length > 0 ? ', partial via ' + via.join(', ') : ', partial') + ')';
    }
    case 'known':
      return 'Known: mapped';
    default:
      return 'None';
  }
}

/** One proof line: 'Proven in range on 2026-09-14 by wazuh:990003 (alerted)'. */
export function proofLine(p: ProofRecord): string {
  return `${PROVEN}${SCOPE_WORDS[p.scope]} on ${p.date.slice(0, 10)} by ${p.detectionRef} (${p.outcome})`;
}

/** The outcome label of a scenario step (P2-12; S7, R21). */
export function scenarioOutcomeLabel(k: 'proven' | 'covered' | 'known' | 'none'): string {
  switch (k) {
    case 'proven': return PROVEN;
    case 'covered': return 'Covered (self-attested or range)';
    case 'known': return 'Known: mapped';
    default: return 'None';
  }
}

/** The menu label of a Phase 2 lens (P2-13, P2-14). */
export function lensLabel(id: 'proven' | 'covered' | 'posture'): string {
  switch (id) {
    case 'proven': return PROVEN;
    case 'covered': return 'Covered (self-attested or range)';
    default: return 'Posture';
  }
}

/**
 * Guards every Covered/Proven render (§1.3). True exactly when at least one
 * state holds a CoveredMark of strength 'full' or 'partial', or a ProofRecord;
 * 'planned' marks alone do not count. Deliberately NOT the D4 predicate
 * (OwnerDataService.hasOwnerData, P2-05): D4 picks the default lens from raw
 * stores at boot, this decides whether Covered or Proven words may render, from
 * the same states that produce the numbers.
 */
export function hasOwnerWords(states: Iterable<Pick<PostureState, 'covered' | 'proof'>>): boolean {
  for (const s of states) {
    if (s.proof.length > 0) return true;
    if (s.covered.some(m => m.strength === 'full' || m.strength === 'partial')) return true;
  }
  return false;
}
