// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { PROVEN, hasOwnerWords, lensLabel, postureBadge, proofLine, scenarioOutcomeLabel } from './posture-vocabulary';
import type { CoveredQualifier } from '../heatmap-modes';
import type { CoveredMark, PostureBucket, PostureState, ProofRecord, ProofScope } from './posture.types';

const BUCKETS: readonly PostureBucket[] = ['none', 'known', 'partial', 'covered', 'proven', 'stale'];
const QUALIFIER_SETS: readonly (readonly CoveredQualifier[])[] = [[], ['self-attested'], ['range'], ['self-attested', 'range'], ['range', 'self-attested']];
const SCOPES: readonly (ProofScope | null)[] = [null, 'production', 'range', 'own-run'];

const mark = (over: Partial<CoveredMark> = {}): CoveredMark => ({
  qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1047', source: 'manual', ...over,
});
const record: ProofRecord = {
  scope: 'range', detectionRef: 'wazuh:990003', outcome: 'alerted', date: '2026-09-14', source: 'lylat-range:CORNERIA-ROOT-01', runId: 'r1',
};

type Badge = Pick<PostureState, 'bucket' | 'qualifiers' | 'proofScope' | 'covered'>;
const badge = (over: Partial<Badge>): string => postureBadge({ bucket: 'none', qualifiers: [], proofScope: null, covered: [], ...over });

describe('posture vocabulary (Phase 2 design §2.4)', () => {
  it('PROVEN is the one Proven-rung word', () => {
    expect(PROVEN).toBe('Proven');
  });

  describe('postureBadge', () => {
    it('[AC] every Covered badge names its qualifier, for every bucket x qualifier combination', () => {
      const markSets: readonly (readonly CoveredMark[])[] = [[], [mark({ strength: 'partial', via: 'M1038' })], [mark({ strength: 'partial', via: undefined })]];
      let coveredSeen = 0;
      for (const bucket of BUCKETS) {
        for (const qualifiers of QUALIFIER_SETS) {
          for (const proofScope of SCOPES) {
            for (const covered of markSets) {
              const text = badge({ bucket, qualifiers, proofScope, covered });
              const ctx = JSON.stringify({ bucket, qualifiers, proofScope, covered: covered.length });
              expect(text.length).withContext(ctx).toBeGreaterThan(0);
              if (/covered/i.test(text)) {
                coveredSeen++;
                expect(text).withContext(ctx).toMatch(/covered\s*\((self-attested|range)/i);
              }
            }
          }
        }
      }
      expect(coveredSeen).withContext('the loop reached the Covered buckets').toBeGreaterThan(0);
    });

    it('[AC] the D16 partial badge reads exactly "Covered (self-attested, partial via M1038)"', () => {
      expect(badge({ bucket: 'partial', qualifiers: ['self-attested'], covered: [mark({ strength: 'partial', via: 'M1038' })] }))
        .toBe('Covered (self-attested, partial via M1038)');
    });

    it('partial: names every distinct partial mitigation once, ignores full and planned marks, and falls back without a via', () => {
      const covered = [
        mark({ strength: 'partial', via: 'M1038' }), mark({ strength: 'full', via: 'M1047' }),
        mark({ strength: 'partial', via: 'M1026' }), mark({ strength: 'partial', via: 'M1038' }), mark({ strength: 'planned', via: 'M1015' }),
      ];
      expect(badge({ bucket: 'partial', qualifiers: ['self-attested'], covered })).toBe('Covered (self-attested, partial via M1038, M1026)');
      expect(badge({ bucket: 'partial', qualifiers: ['self-attested'], covered: [mark({ strength: 'partial', via: undefined })] }))
        .toBe('Covered (self-attested, partial)');
      expect(badge({ bucket: 'partial', qualifiers: ['range'], covered: [mark({ strength: 'partial', via: 'M1038', qualifier: 'range' })] }))
        .toBe('Covered (range, partial via M1038)');
    });

    it('covered: the qualifier forms', () => {
      expect(badge({ bucket: 'covered', qualifiers: ['self-attested'] })).toBe('Covered (self-attested)');
      expect(badge({ bucket: 'covered', qualifiers: ['range'] })).toBe('Covered (range)');
      expect(badge({ bucket: 'covered', qualifiers: ['self-attested', 'range'] })).toBe('Covered (self-attested, range)');
      expect(badge({ bucket: 'covered', qualifiers: ['range', 'self-attested'] })).toBe('Covered (self-attested, range)');
    });

    it('proven and stale: composed from PROVEN with the proof scope', () => {
      expect(badge({ bucket: 'proven', proofScope: 'range' })).toBe(`${PROVEN} in range`);
      expect(badge({ bucket: 'proven', proofScope: 'production' })).toBe(`${PROVEN} in production`);
      expect(badge({ bucket: 'proven', proofScope: 'own-run' })).toBe(`${PROVEN} (your run)`);
      expect(badge({ bucket: 'stale', proofScope: 'range' })).toBe(`${PROVEN} in range (stale)`);
      expect(badge({ bucket: 'proven', proofScope: null })).toBe(PROVEN);
    });

    it('known and none', () => {
      expect(badge({ bucket: 'known' })).toBe('Known: mapped');
      expect(badge({ bucket: 'none' })).toBe('None');
    });
  });

  it('proofLine: scope, date, the named detection and the outcome, composed from PROVEN', () => {
    expect(proofLine(record)).toBe(`${PROVEN} in range on 2026-09-14 by wazuh:990003 (alerted)`);
    expect(proofLine({ ...record, scope: 'own-run', outcome: 'blocked', date: '2026-09-21T23:59:00.000Z', detectionRef: 'sigma:abc' }))
      .toBe(`${PROVEN} (your run) on 2026-09-21 by sigma:abc (blocked)`);
  });

  it('scenarioOutcomeLabel and lensLabel', () => {
    expect(scenarioOutcomeLabel('proven')).toBe(PROVEN);
    expect(scenarioOutcomeLabel('covered')).toBe('Covered (self-attested or range)');
    expect(scenarioOutcomeLabel('known')).toBe('Known: mapped');
    expect(scenarioOutcomeLabel('none')).toBe('None');
    expect(lensLabel('proven')).toBe(PROVEN);
    expect(lensLabel('covered')).toBe('Covered (self-attested or range)');
    expect(lensLabel('posture')).toBe('Posture');
    for (const text of [scenarioOutcomeLabel('covered'), lensLabel('covered')]) {
      expect(text).toMatch(/covered\s*\((self-attested|range)/i);
    }
  });

  describe('hasOwnerWords (Revision 3: at least one full or partial mark, or a proof)', () => {
    const state = (covered: readonly CoveredMark[], proof: readonly ProofRecord[] = []) => ({ covered, proof });

    it('false for no states', () => {
      expect(hasOwnerWords([])).toBeFalse();
    });

    it('false when the only marks are planned', () => {
      expect(hasOwnerWords([state([mark({ strength: 'planned' })]), state([])])).toBeFalse();
    });

    it('true for one full mark, one partial mark and one ProofRecord', () => {
      expect(hasOwnerWords([state([]), state([mark()])])).toBeTrue();
      expect(hasOwnerWords([state([mark({ strength: 'partial', via: 'M1038' })])])).toBeTrue();
      expect(hasOwnerWords([state([], [record])])).toBeTrue();
    });

    it('true for one controls-derived mark (the controls-only case)', () => {
      expect(hasOwnerWords([state([mark({ basis: 'control-implemented', via: 'ctl-1' })])])).toBeTrue();
    });

    it('accepts any iterable', () => {
      expect(hasOwnerWords(new Set([state([mark()])]).values())).toBeTrue();
    });
  });
});
