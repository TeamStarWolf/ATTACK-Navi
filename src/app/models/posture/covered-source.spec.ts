// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 43: Covered splits by source, as decision 36 split partial by cause.
// Round 8 read "You recorded a mitigation, control, confirmation or run (self-attested)"
// on T1005, T1037.001 and T1550.002, whose only full mark was a range row.
import type { CoveredMark, PostureState } from './posture.types';
import { DEFAULT_POSTURE_RULES, derivePosture } from './derive-posture';
import { coveredSourceLines, coveredSourceReason, coveredSourcesOf, tallyCoveredSources } from './covered-source';
import { runInputsFor } from '../../services/posture-adapters';
import { rpf8Runs } from '../../testing/rpf8-shapes';

const SELF = 'Covered (self-attested: mitigation, control, confirmation or your run)';
const RANGE = 'Covered (range: lab-validated detection)';
const MIT: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1036', source: 'manual' };

function derive(attackId: string, extra: readonly CoveredMark[] = []): PostureState {
  const inputs = runInputsFor(rpf8Runs().get(attackId) ?? []);
  return derivePosture(`attack/enterprise/${attackId}@19.2`, {
    knownSignals: 2, threatWeight: 1, exposureWeight: 0, covered: [...extra, ...inputs.flatMap(i => i.covered)],
    proof: inputs.flatMap(i => i.proof), verdicts: inputs.flatMap(i => i.verdicts), runs: inputs.map(i => i.summary),
  }, DEFAULT_POSTURE_RULES, new Date(2026, 9, 23, 12));
}

describe('RP-F decision 43: Covered by source', () => {
  for (const id of ['T1005', 'T1037.001', 'T1550.002']) {
    it(`${id} (a range-only full mark) reads the range label, never the self-attested one`, () => {
      const s = derive(id);
      expect(s.bucket).toBe('covered');
      expect(coveredSourcesOf(s)).toEqual(['range']);
      expect(coveredSourceReason(s)).toBe(RANGE);
      expect(coveredSourceReason(s)).not.toContain('self-attested');
    });
  }

  it('a self-attested technique reads the self-attested label; a technique with both names both', () => {
    const self = derive('T9999', [MIT]);
    expect(coveredSourceReason(self)).toBe(SELF);
    const both = derive('T1037.001', [MIT]);
    expect(coveredSourcesOf(both)).toEqual(['self-attested', 'range']);
    expect(coveredSourceReason(both)).toBe(`${SELF}; ${RANGE}`);
  });

  it('counts each Covered technique under each of its sources, and lists a line per source with a count', () => {
    const states = [derive('T1005'), derive('T1550.002'), derive('T9999', [MIT]), derive('T1037.001', [MIT]), derive('T1113')];
    const tally = tallyCoveredSources(states);
    expect(tally).toEqual({ 'self-attested': 2, range: 3 });
    expect(coveredSourceLines(tally)).toEqual([`${SELF}: 2`, `${RANGE}: 3`]);
    expect(coveredSourceLines({ 'self-attested': 0, range: 1 })).toEqual([`${RANGE}: 1`]);
  });

  it('names no source outside the Covered bucket; a hand-built state with none reads the lens label', () => {
    expect(coveredSourcesOf(derive('T1113'))).toEqual([]);
    expect(coveredSourceReason({ bucket: 'covered', covered: [] })).toBe('Covered (self-attested or range)');
  });
});
