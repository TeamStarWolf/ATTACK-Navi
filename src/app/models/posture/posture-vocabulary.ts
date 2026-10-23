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
import { validationDay } from '../local-date';

// truth-vocab-allow-next-line proven-only -- the Proven-rung word; every caller passes Proven-rung data
export const PROVEN = 'Proven';

// The Proven wording names the run's source (RP-F decision 35): "your run" only for a
// manual run, "range run" for a contract-imported (range) run. PR #240 round 1: the
// cell tooltip and aria-label of a range proof read "Proven in range", which named
// neither.
const SCOPE_WORDS: Readonly<Record<ProofScope, string>> = {
  production: ' in production',
  range: ' in a range run',
  'own-run': ' (your run)',
};

/** The words after PROVEN for a proof scope ('' for none): ' in a range run', ' (your run)', ' in production'. */
export function provenScopeWords(scope: ProofScope | null): string {
  return scope ? SCOPE_WORDS[scope] : '';
}

const QUALIFIER_ORDER: readonly CoveredQualifier[] = ['self-attested', 'range'];

/**
 * The qualifiers a Covered badge names: the state's own `qualifiers`, or, when
 * that set is empty, the qualifiers of the marks that make the bucket (full
 * marks for 'covered', partial marks for 'partial'). Never a default: an empty
 * answer means the data holds no qualifier and the badge must not say Covered.
 */
function badgeQualifiers(s: Pick<PostureState, 'bucket' | 'qualifiers' | 'covered'>): readonly CoveredQualifier[] {
  if (s.qualifiers.length > 0) return s.qualifiers;
  const strength = s.bucket === 'covered' ? 'full' : 'partial';
  return QUALIFIER_ORDER.filter(q => s.covered.some(m => m.strength === strength && m.qualifier === q));
}

/** The Covered head for a qualifier set, open so the partial form can continue it; null for no qualifier. */
function coveredHead(qualifiers: readonly CoveredQualifier[]): string | null {
  const self = qualifiers.includes('self-attested');
  const range = qualifiers.includes('range');
  if (self && range) return 'Covered (self-attested, range';
  if (range) return 'Covered (range';
  if (self) return 'Covered (self-attested';
  return null;
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
 *   'Proven in a range run' | 'Proven in production' | 'Proven (your run)' | 'Proven in a range run (stale)'
 *   'Covered (self-attested)' | 'Covered (range)' | 'Covered (self-attested, range)'
 *   'Covered (self-attested, partial via M1038)'   (D16; passes covered-unqualified)
 *   'Known: mapped' | 'None'
 * A 'covered' or 'partial' state names its own qualifiers (D5); with an empty
 * `qualifiers` set they come from its marks, and with no qualified mark at all
 * the badge is 'None' rather than an unbacked Covered claim.
 */
export function postureBadge(s: Pick<PostureState, 'bucket' | 'qualifiers' | 'proofScope' | 'covered'>): string {
  switch (s.bucket) {
    case 'proven':
    case 'stale': {
      return PROVEN + provenScopeWords(s.proofScope) + (s.bucket === 'stale' ? ' (stale)' : '');
    }
    case 'covered': {
      const head = coveredHead(badgeQualifiers(s));
      return head === null ? 'None' : head + ')';
    }
    case 'partial': {
      const head = coveredHead(badgeQualifiers(s));
      if (head === null) return 'None';
      const via = partialVia(s.covered);
      return head + (via.length > 0 ? ', partial via ' + via.join(', ') : ', partial') + ')';
    }
    case 'known':
      return 'Known: mapped';
    default:
      return 'None';
  }
}

/** One proof line: 'Proven in a range run on 9/14/26 by wazuh:990003 (alerted)'. */
export function proofLine(p: ProofRecord): string {
  return `${PROVEN}${SCOPE_WORDS[p.scope]} on ${validationDay(p.date)} by ${p.detectionRef} (${p.outcome})`;
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

/**
 * What the range's own word for its proof is, as one identifier-like word: the range
 * Covered label names the kind of evidence the range reports (RP-F decision 43).
 */
const LAB_VALIDATED = 'lab-validated';

/**
 * Covered by source (RP-F decision 43): the label of each source of a Covered technique,
 * as the scenario table's reason and the Report Builder's Covered card (HTML and PDF too)
 * name it. Each names its qualifier right after the word (covered-unqualified).
 */
export const COVERED_SOURCE_LABELS: Readonly<Record<CoveredQualifier, string>> = {
  'self-attested': 'Covered (self-attested: mitigation, control, confirmation or your run)',
  range: `Covered (range: ${LAB_VALIDATED} detection)`,
};

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
