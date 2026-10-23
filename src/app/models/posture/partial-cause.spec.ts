// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// partial-cause.ts: the words of a partial mark's typed cause (RP-F decisions 31 and
// 35). The telemetry cause carries its row's outcome; the words follow it.
import type { CoveredMark, TelemetryOutcome } from './posture.types';
import {
  BREADTH_PARTIAL_WORDS, partialMarkWords, partialReason, recordRunTooltip, telemetryPartialWords,
} from './partial-cause';
import { runSourceWords } from './proof-gap';

const telemetry = (via: string | undefined, telemetryOutcome?: TelemetryOutcome): CoveredMark => ({
  qualifier: 'range', basis: 'range-telemetry-observed', strength: 'partial', source: 'lylat-range:m1', partialCause: 'telemetry',
  ...(via ? { via } : {}), ...(telemetryOutcome ? { telemetryOutcome } : {}),
});
const BREADTH: CoveredMark = {
  qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual', partialCause: 'breadth',
};
const NOT_PROOF = 'but the range reports telemetry-only coverage, so it is not proof';

describe('partial-cause (RP-F decisions 31 and 35)', () => {
  it('a row with outcome logged or none keeps the no-alert words', () => {
    for (const o of ['logged', 'none'] as const) {
      expect(telemetryPartialWords([telemetry('wazuh:5', o)])).toBe('range telemetry observed via wazuh:5: partial, no detection alerted');
    }
    // A hand-built mark without an outcome reads as no detection alerted.
    expect(telemetryPartialWords([telemetry('wazuh:5')])).toBe('range telemetry observed via wazuh:5: partial, no detection alerted');
  });

  it('a row whose rule alerted or blocked names the outcome, and says it is not proof', () => {
    expect(telemetryPartialWords([telemetry('wazuh:12', 'alerted')]))
      .toBe(`range telemetry observed via wazuh:12: partial; the rule alerted in this run, ${NOT_PROOF}`);
    expect(telemetryPartialWords([telemetry('wazuh:13', 'blocked')]))
      .toBe(`range telemetry observed via wazuh:13: partial; the rule blocked in this run, ${NOT_PROOF}`);
  });

  it('rows of different outcomes are named in groups, quiet rows first; several rules read "the rules"', () => {
    const marks = [telemetry('wazuh:12', 'alerted'), telemetry('wazuh:5', 'logged'), telemetry('wazuh:14', 'alerted'), telemetry('wazuh:13', 'blocked')];
    expect(telemetryPartialWords(marks)).toBe(
      'range telemetry observed via wazuh:5: partial, no detection alerted; '
      + `range telemetry observed via wazuh:12, wazuh:14: partial; the rules alerted in this run, ${NOT_PROOF}; `
      + `range telemetry observed via wazuh:13: partial; the rule blocked in this run, ${NOT_PROOF}`);
  });

  it('only telemetry partial marks are words; with none, or no rule, the bare no-alert words', () => {
    expect(telemetryPartialWords([BREADTH])).toBe('range telemetry observed: partial, no detection alerted');
    expect(telemetryPartialWords([])).toBe('range telemetry observed: partial, no detection alerted');
    expect(telemetryPartialWords([telemetry(undefined, 'alerted')])).toBe(`range telemetry observed: partial; the rule alerted in this run, ${NOT_PROOF}`);
  });

  it('partialReason reads the alerted words after the badge, and after the threshold sentence for a mixed state', () => {
    const alerted = telemetry('wazuh:14', 'alerted');
    expect(partialReason({ covered: [alerted], partialCauses: ['telemetry'] }))
      .toBe(` from range telemetry observed via wazuh:14: partial; the rule alerted in this run, ${NOT_PROOF}`);
    expect(partialReason({ covered: [BREADTH, alerted], partialCauses: ['breadth', 'telemetry'] }))
      .toBe(`: ${BREADTH_PARTIAL_WORDS}; range telemetry observed via wazuh:14: partial; the rule alerted in this run, ${NOT_PROOF}`);
  });

  it('partialMarkWords names one mark by its own cause; the Record-a-run tooltip starts with the same words', () => {
    expect(partialMarkWords(telemetry('wazuh:12', 'alerted'))).toBe(`range telemetry observed via wazuh:12: partial; the rule alerted in this run, ${NOT_PROOF}`);
    expect(partialMarkWords(BREADTH)).toBe(BREADTH_PARTIAL_WORDS);
    expect(partialMarkWords({ ...BREADTH, strength: 'full' })).toBeNull();
    expect(partialMarkWords({ ...BREADTH, partialCause: undefined })).toBeNull();
    expect(recordRunTooltip(telemetry('wazuh:13', 'blocked')))
      .toBe(`range telemetry observed via wazuh:13: partial; the rule blocked in this run, ${NOT_PROOF}; record a validation run of this technique in Detect > Validation`);
  });

  it('a run is named "your run" only when you recorded it; a contract-imported run is the range run', () => {
    expect(runSourceWords('manual')).toBe('your run');
    expect(runSourceWords('lylat-range:SYNTH-MISSION-A')).toBe('the range run');
    expect(runSourceWords('layer:x')).toBe('the imported run');
  });
});
