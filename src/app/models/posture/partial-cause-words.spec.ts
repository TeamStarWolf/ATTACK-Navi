// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 36: threshold or breadth wording outside partial-cause.ts is a defect.
// Every surface that words a partial (the why line and the cell, the scenario table's
// reason, the Report Builder's partial card and note, which the HTML and PDF reports
// print too, and the Posture and Covered lens formulas) must take its cause words from
// partial-cause.ts. This spec renders each surface's words for a breadth partial, a
// range telemetry partial (quiet, alerted, blocked) and a mixed one, removes every
// phrase partial-cause.ts exports, and fails on any cause wording left over: a literal
// written beside the module (round 7: the scenario table's "a broad mitigation marked
// implemented" and the report card's "broad mitigation" on telemetry-only rows).
import type { CoveredMark, PartialCause, PostureState, TelemetryOutcome } from './posture.types';
import {
  BREADTH_PARTIAL_WORDS, PARTIAL_CAUSES_FORMULA, PARTIAL_CAUSES_NOTE, PARTIAL_CAUSE_LABELS, partialCauseLines,
  partialCauseReason, partialMarkWords, recordRunTooltip, telemetryPartialWords,
} from './partial-cause';
import { heatmapModeDef } from '../heatmap-modes';
import { lensExplain } from '../lens-explain';
import { postureCellLabel } from './posture-ramp';
import { REPORT_SPLIT_LABELS, partialCardLines } from '../report-split';
import { scenarioReason } from '../../components/scenario-panel/scenario-panel.component';
import { DEFAULT_POSTURE_RULES } from './derive-posture';

/** Cause wording: the breadth threshold, a broad mitigation, or a telemetry partial's tail. */
const CAUSE_WORDING = /breadth|threshold|broad mitigation|mapped to more techniques|no detection alerted|no alert credited|telemetry-only/i;

const BREADTH: CoveredMark = {
  qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual', partialCause: 'breadth',
};
const telemetry = (via: string, telemetryOutcome: TelemetryOutcome): CoveredMark => ({
  qualifier: 'range', basis: 'range-telemetry-observed', strength: 'partial', via, source: 'lylat-range:m1', partialCause: 'telemetry', telemetryOutcome,
});

function partialState(covered: readonly CoveredMark[], causes: readonly PartialCause[]): PostureState {
  return {
    ref: 'attack/enterprise/T1106@19.2', rung: 'covered', bucket: 'partial',
    qualifiers: [...new Set(covered.map(m => m.qualifier))], subStates: ['partial'], covered, proof: [],
    proofScope: null, proofAge: null, knownSignals: 2, threatWeight: 1, exposureWeight: 0, excluded: false,
    runsWithoutProof: [], partialCauses: causes,
  };
}

const STATES: readonly PostureState[] = [
  partialState([BREADTH], ['breadth']),
  partialState([telemetry('wazuh:5', 'logged')], ['telemetry']),
  partialState([telemetry('wazuh:12', 'alerted')], ['telemetry']),
  partialState([telemetry('wazuh:13', 'blocked')], ['telemetry']),
  partialState([BREADTH, telemetry('wazuh:14', 'alerted'), telemetry('wazuh:5', 'none')], ['breadth', 'telemetry']),
];

/** Every phrase partial-cause.ts exports for these states, longest first so a longer phrase is removed whole. */
function moduleWords(): string[] {
  const words = new Set<string>([
    BREADTH_PARTIAL_WORDS, PARTIAL_CAUSES_FORMULA, PARTIAL_CAUSES_NOTE, ...Object.values(PARTIAL_CAUSE_LABELS),
  ]);
  for (const s of STATES) {
    words.add(telemetryPartialWords(s.covered));
    for (const m of s.covered) {
      const w = partialMarkWords(m);
      if (w) words.add(w);
      if (m.partialCause === 'telemetry') {
        words.add(telemetryPartialWords([m]));
        words.add(recordRunTooltip(m));
      }
    }
  }
  return [...words].sort((a, b) => b.length - a.length);
}

/** `text` with every partial-cause.ts phrase removed. */
function residue(text: string): string {
  let out = text;
  for (const w of moduleWords()) out = out.split(w).join(' ');
  return out;
}

/** The words each surface decision 36 names prints for a partial. */
function surfaceWords(): { readonly surface: string; readonly text: string }[] {
  const out: { surface: string; text: string }[] = [];
  const windows = DEFAULT_POSTURE_RULES.decayDays;
  for (const mode of ['posture', 'covered'] as const) {
    const def = heatmapModeDef(mode)!;
    out.push({ surface: `${mode} lens formula`, text: def.formula });
    STATES.forEach((s, i) => {
      const cell = def.project!({ posture: () => s } as never, { id: 'attack-pattern--t1106', attackId: 'T1106' } as never);
      out.push({ surface: `${mode} why line, state ${i}`, text: lensExplain(def, cell, { state: s, decayDays: windows }) });
      out.push({
        surface: `${mode} cell label, state ${i}`,
        text: postureCellLabel(s, windows, mode === 'posture' ? undefined : { value: mode, words: cell.label }, { bucket: cell.bucket!, subStates: cell.subStates! }),
      });
    });
  }
  STATES.forEach((s, i) => out.push({ surface: `scenario reason, state ${i}`, text: scenarioReason(s, 3) }));
  for (const [key, label] of Object.entries(REPORT_SPLIT_LABELS)) out.push({ surface: `REPORT_SPLIT_LABELS.${key}`, text: label });
  out.push({ surface: 'report partial card lines', text: partialCardLines({ partialByCause: { breadth: 2, telemetry: 3 } }).join('\n') });
  out.push({ surface: 'scenario partial note lines', text: partialCauseLines({ breadth: 1, telemetry: 1 }).join('\n') });
  STATES.forEach((s, i) => out.push({ surface: `partialCauseReason, state ${i}`, text: partialCauseReason(s) }));
  return out;
}

describe('partial cause wording lives in partial-cause.ts (RP-F decision 36)', () => {
  it('every partial surface takes its cause words from partial-cause.ts: no threshold or breadth wording is left once its phrases are removed', () => {
    const words = surfaceWords();
    expect(words.length).toBeGreaterThan(40);
    for (const { surface, text } of words) {
      expect(residue(text)).withContext(`${surface}: ${text}`).not.toMatch(CAUSE_WORDING);
    }
  });

  it('a telemetry partial is never worded with the breadth cause, on any of those surfaces', () => {
    const telemetryOnly = STATES.slice(1, 4);
    for (const s of telemetryOnly) {
      for (const mode of ['posture', 'covered'] as const) {
        const def = heatmapModeDef(mode)!;
        const cell = def.project!({ posture: () => s } as never, { id: 'attack-pattern--t1106', attackId: 'T1106' } as never);
        expect(lensExplain(def, cell, { state: s })).not.toMatch(/breadth|broad mitigation/);
      }
      expect(scenarioReason(s, 3)).not.toMatch(/breadth|broad mitigation/);
    }
  });

  it('the check catches a literal written beside the module', () => {
    expect(residue('Partly recorded: a broad mitigation marked implemented, not confirmed per technique')).toMatch(CAUSE_WORDING);
    expect(residue('partial (broad mitigation, not confirmed per technique)')).not.toMatch(CAUSE_WORDING);
  });
});
