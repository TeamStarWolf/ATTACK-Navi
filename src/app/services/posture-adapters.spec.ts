// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The store adapters of PostureService (Phase 2 design §3 P2-05), as pure
// functions over the lens fixture (src/testing/fixtures/enterprise-lens.stix.json).
import type { Domain } from '../models/domain';
import type { Technique } from '../models/technique';
import type { SecurityControl } from '../models/security-control';
import { ControlsService } from './controls.service';
import type { ImplStatus } from './implementation.service';
import type { TechniqueMarkRecord } from './technique-marks.service';
import type { ValidationOutcome, ValidationRunV2 } from './validation.service';
import { fixtureControls, parseFixtureDomain } from '../testing/lens-harness';
import { firedRules } from '../models/posture/fired-rules';
import { telemetryPartialWords } from '../models/posture/partial-cause';
import {
  classifyImplKey, controlsAdapter, implView, implementationAdapter, markKey, matchToTechniques,
  runInputs, techniqueMarkToCovered, telemetryMark,
} from './posture-adapters';

const identity = (id: string) => id;

function run(over: Partial<ValidationRunV2> = {}): ValidationRunV2 {
  return {
    id: 'r1', techniqueId: 'T1003', techniqueName: '', runDate: '2026-09-20T10:00:00.000Z', operator: '',
    telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '',
    attackResult: 'executed', detectionsExpected: [], detectionsFired: [],
    responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status: 'untested',
    domain: 'enterprise', attackVersion: '19.2', source: 'manual',
    createdAt: '2026-09-20T10:00:00.000Z', updatedAt: '2026-09-20T10:00:00.000Z',
    techniqueRef: 'attack/enterprise/T1003@19.2', proofScope: 'own-run', outcomes: [], statusFromSource: false,
    ...over,
  };
}

const outcome = (o: Partial<ValidationOutcome> & Pick<ValidationOutcome, 'outcome'>): ValidationOutcome =>
  ({ detectionRef: null, ...o });

describe('posture adapters (P2-05)', () => {
  let domain: Domain;
  const mit = (attackId: string) => domain.mitigations.find(m => m.attackId === attackId)!;
  const tech = (attackId: string) => domain.techniques.find(t => t.attackId === attackId)!;

  beforeEach(() => {
    domain = parseFixtureDomain();
  });

  describe('classifyImplKey', () => {
    it('names mitigation keys, wizard technique keys and everything else', () => {
      expect(classifyImplKey('course-of-action--1')).toBe('mitigation');
      expect(classifyImplKey('attack-pattern--1')).toBe('technique');
      expect(classifyImplKey('M1036')).toBe('unmatched');
      expect(classifyImplKey('course-of-action--')).toBe('unmatched');
      expect(classifyImplKey('x-mitre-tactic--1')).toBe('unmatched');
    });
  });

  describe('implementation adapter', () => {
    it('rolls mitigations up with the breadth guard: M1047 (13) full, M1026 (16) partial at 15', () => {
      const impl = new Map<string, ImplStatus>([[mit('M1047').id, 'implemented'], [mit('M1026').id, 'implemented']]);
      const { marks, unmatched } = implementationAdapter(impl, domain, 15);
      expect(unmatched).toEqual([]);
      for (const t of domain.techniquesByMitigation.get(mit('M1047').id)!) {
        expect(marks.get(t.id)!.some(m => m.via === 'M1047' && m.strength === 'full')).withContext(t.attackId).toBeTrue();
      }
      for (const t of domain.techniquesByMitigation.get(mit('M1026').id)!) {
        expect(marks.get(t.id)!.some(m => m.via === 'M1026' && m.strength === 'partial')).withContext(t.attackId).toBeTrue();
      }
    });

    it("turns wizard technique ratings into 'technique-confirmed' marks from source 'wizard'", () => {
      const t = tech('T1593');
      const impl = new Map<string, ImplStatus>([[t.id, 'implemented'], [tech('T1005').id, 'planned'], [tech('T1006').id, 'not-started']]);
      const { marks } = implementationAdapter(impl, domain, 15);
      expect(marks.get(t.id)).toEqual([{ qualifier: 'self-attested', basis: 'technique-confirmed', strength: 'full', source: 'wizard' }]);
      expect(marks.get(tech('T1005').id)![0].strength).toBe('planned');
      expect(marks.has(tech('T1006').id)).toBeFalse();
    });

    it('lists every other key as unmatched, with a reason, and keeps it out of the marks', () => {
      const impl = new Map<string, ImplStatus>([['M1036', 'implemented'], ['junk key', 'planned']]);
      const { marks, unmatched } = implementationAdapter(impl, domain, 15);
      expect(marks.size).toBe(0);
      expect(unmatched.map(u => u.key)).toEqual(['M1036', 'junk key']);
      expect(unmatched.every(u => u.store === 'impl' && u.reason.length > 0)).toBeTrue();
      expect(unmatched[0].reason).toContain('bare ATT&CK id');
    });
  });

  describe('controls adapter', () => {
    it("follows computeCoverage's hop: the same techniques, implemented and planned", () => {
      const controls = fixtureControls(domain);
      const marks = controlsAdapter(controls, domain, 500);
      const { coveredIds, plannedIds } = new ControlsService().computeCoverage(controls, domain);
      const withFull = new Set([...marks].filter(([, ms]) => ms.some(m => m.strength !== 'planned')).map(([id]) => id));
      const plannedOnly = new Set([...marks].filter(([, ms]) => ms.every(m => m.strength === 'planned')).map(([id]) => id));
      expect(coveredIds.size).toBeGreaterThan(0);
      expect(plannedIds.size).toBeGreaterThan(0);
      expect([...withFull].sort()).toEqual([...coveredIds].sort());
      expect([...plannedOnly].sort()).toEqual([...plannedIds].sort());
    });

    it('applies the breadth guard per mitigation and names the mitigation', () => {
      const ctrl: SecurityControl = {
        id: 'c1', name: 'c', framework: 'Custom', controlRef: 'x', description: '',
        mitigationIds: [mit('M1047').id, mit('M1026').id], status: 'implemented',
      };
      const marks = controlsAdapter([ctrl], domain, 15);
      const m1047 = domain.techniquesByMitigation.get(mit('M1047').id)!;
      const m1026 = domain.techniquesByMitigation.get(mit('M1026').id)!;
      for (const t of m1047) expect(marks.get(t.id)!.find(m => m.via === 'M1047')!.strength).toBe('full');
      for (const t of m1026) expect(marks.get(t.id)!.find(m => m.via === 'M1026')!.strength).toBe('partial');
      // RP-F decision 31: a partial control mark is partial by breadth; a full one names no cause.
      for (const t of m1026) expect(marks.get(t.id)!.find(m => m.via === 'M1026')!.partialCause).toBe('breadth');
      for (const t of m1047) expect(marks.get(t.id)!.find(m => m.via === 'M1047')!.partialCause).toBeUndefined();
      expect([...marks.values()].flat().every(m => m.basis === 'control-implemented' && m.qualifier === 'self-attested')).toBeTrue();
    });

    it('ignores a mitigation the loaded domain does not have', () => {
      const ctrl: SecurityControl = {
        id: 'c1', name: 'c', framework: 'Custom', controlRef: 'x', description: '',
        mitigationIds: ['course-of-action--not-here'], status: 'implemented',
      };
      expect(controlsAdapter([ctrl], domain, 15).size).toBe(0);
    });
  });

  describe('telemetry adapter', () => {
    it('is n/a for an unmapped technique, never a mark', () => {
      expect(telemetryMark([], new Set(['anything']))).toBeNull();
    });

    it('needs every required key configured', () => {
      expect(telemetryMark(['a::1', 'b::2'], new Set(['a::1']))).toBeNull();
      expect(telemetryMark(['a::1', 'b::2'], new Set(['a::1', 'b::2']))).toEqual({
        qualifier: 'self-attested', basis: 'telemetry-configured', strength: 'full', via: 'a::1, b::2', source: 'manual',
      });
    });
  });

  describe('validation adapter (S4)', () => {
    it('gives one ProofRecord per fired detection, scoped by proofScope', () => {
      const r = runInputs(run({ detectionsFired: ['sigma:a', 'sigma:b', 'sigma:a'], outcomes: [outcome({ outcome: 'alerted', detectionRef: 'sigma:a' })] }));
      expect(r.proof.map(p => [p.detectionRef, p.outcome, p.scope])).toEqual([
        ['sigma:a', 'alerted', 'own-run'], ['sigma:b', 'alerted', 'own-run'],
      ]);
      expect(r.proof[0]).toEqual(jasmine.objectContaining({ date: '2026-09-20T10:00:00.000Z', source: 'manual', runId: 'r1' }));
      expect(r.covered).toEqual([]);
    });

    it("every proof record carries its run's fired-rule count, the summary's (RP-F decision 30b, round 1)", () => {
      const r = runInputs(run({
        detectionsFired: ['sigma:a', 'sigma:b'], outcomes: [outcome({ outcome: 'blocked', detectionRef: 'edr:c' }), outcome({ outcome: 'logged', detectionRef: 'siem:l' })],
      }));
      expect(r.summary.rulesFired).toBe(3);
      expect(r.proof.map(p => [p.detectionRef, p.runRulesFired])).toEqual([['edr:c', 3], ['sigma:a', 3], ['sigma:b', 3]]);
    });

    it("an 'alerted' outcome with a detectionRef is proof even without detectionsFired; one without is not", () => {
      const r = runInputs(run({ outcomes: [outcome({ outcome: 'alerted', detectionRef: 'wazuh:1' }), outcome({ outcome: 'alerted' })] }));
      expect(r.proof.map(p => p.detectionRef)).toEqual(['wazuh:1']);
    });

    it("a blocked run with a named detection is proof with outcome 'blocked'", () => {
      const r = runInputs(run({ attackResult: 'blocked', detectionsFired: ['edr:1'] }));
      expect(r.proof.map(p => [p.detectionRef, p.outcome])).toEqual([['edr:1', 'blocked']]);
      expect(r.covered).toEqual([]);
      const viaOutcome = runInputs(run({ outcomes: [outcome({ outcome: 'blocked', detectionRef: 'edr:2' })] }));
      expect(viaOutcome.proof.map(p => p.outcome)).toEqual(['blocked']);
    });

    it("a passed blocked run with no named detection is a full self-attested 'own-run-blocked' mark, never proof", () => {
      const r = runInputs(run({ status: 'passed', attackResult: 'blocked', outcomes: [outcome({ outcome: 'blocked' })] }));
      expect(r.proof).toEqual([]);
      expect(r.covered).toEqual([{
        qualifier: 'self-attested', basis: 'own-run-blocked', strength: 'full', source: 'manual', at: '2026-09-20T10:00:00.000Z',
      }]);
    });

    // RP-F decision 23: the own-run-blocked mark is gated on the proof allow-list. Record
    // Run's "Blocked by control" with no expected rule stores 'untested' (T1069), and a
    // seeded failed run with a blocked outcome (S26 T1027) read Covered beside a FAIL pill.
    for (const status of ['untested', 'partial', 'not-reproducible', 'failed', 'no-telemetry'] as const) {
      it(`a ${status} run with a blocked outcome and no named rule attests nothing`, () => {
        const r = runInputs(run({ status, attackResult: 'blocked', outcomes: [outcome({ outcome: 'blocked' })] }));
        expect(r.covered).toEqual([]);
        expect(r.proof).toEqual([]);
      });
    }

    it('carries the run itself (id, status, date, source) for the runs-without-proof line (RP-F decision 9)', () => {
      expect(runInputs(run({ status: 'untested' })).summary).toEqual({
        runId: 'r1', status: 'untested', date: '2026-09-20T10:00:00.000Z', source: 'manual', rulesFired: 0, rules: [],
      });
      // RP-F decision 28: the named rules the run lists as fired, whatever its status (the pill's count).
      expect(runInputs(run({ status: 'untested', detectionsFired: ['siem:a', 'siem:b', 'siem:a'] })).summary.rulesFired).toBe(2);
    });

    it('counts fired rules through firedRules: detectionsFired and the rules of alerted or blocked outcomes, each once (RP-F decision 30b)', () => {
      // Round 5: a blocked outcome naming a rule, with nothing in detectionsFired, read
      // "1 rule fired" on the card beside a pill "0 of 0". Both now count it (pill: 1 of 0).
      const blockedNamed = runInputs(run({
        status: 'untested', attackResult: 'blocked', detectionsFired: [],
        outcomes: [outcome({ detectionRef: 'edr:block-1', outcome: 'blocked' })],
      }));
      expect(blockedNamed.summary.rulesFired).toBe(1);
      const alertedNamed = runInputs(run({
        status: 'untested', detectionsFired: [], outcomes: [outcome({ detectionRef: 'siem:x', outcome: 'alerted' })],
      }));
      expect(alertedNamed.summary.rulesFired).toBe(1);
      // A logged or none outcome fired nothing; a rule in both lists counts once.
      const mixed = runInputs(run({
        status: 'untested', detectionsFired: ['siem:x'],
        outcomes: [outcome({ detectionRef: ' siem:x ', outcome: 'alerted' }), outcome({ detectionRef: 'siem:l', outcome: 'logged' }), outcome({ detectionRef: 'siem:n', outcome: 'none' })],
      }));
      expect(mixed.summary.rulesFired).toBe(1);
      // Blank entries are not rules; each listed rule counts once.
      expect(runInputs(run({ status: 'untested', detectionsFired: [' ', 'siem:a', ' siem:a '] })).summary.rulesFired).toBe(1);
    });

    // RP-F decision 29: proof supersession is per rule, so the summary carries every rule the
    // run names (outcomes, expected, fired), trimmed, each once, for derivePosture's sameRule.
    it('names every rule of the run, from its outcomes, expected and fired lists, each once (RP-F decision 29)', () => {
      const r = runInputs(run({
        status: 'failed', detectionsExpected: ['siem:a', ' siem:b '], detectionsFired: ['siem:a', ''],
        outcomes: [outcome({ detectionRef: 'edr:c', outcome: 'blocked' }), outcome({ detectionRef: null, outcome: 'none' }), outcome({ detectionRef: ' siem:a', outcome: 'alerted' })],
      }));
      expect(r.summary.rules).toEqual(['edr:c', 'siem:a', 'siem:b']);
    });

    it("'failed' is a failed verdict and 'not-reproducible' a notReproducible one", () => {
      expect(runInputs(run({ status: 'failed' })).verdicts).toEqual([
        { date: '2026-09-20T10:00:00.000Z', failed: true, notReproducible: false, source: 'manual' },
      ]);
      expect(runInputs(run({ status: 'not-reproducible' })).verdicts[0].notReproducible).toBeTrue();
      expect(runInputs(run({ outcomes: [outcome({ outcome: 'none', negativeControl: 'not-reproducible' })] })).verdicts[0].notReproducible).toBeTrue();
      expect(runInputs(run({ status: 'passed' })).verdicts).toEqual([]);
    });

    it('turns range coverage states into range marks; own runs never carry them', () => {
      const outcomes = [
        outcome({ outcome: 'none', detectionRef: 'wazuh:9', coverageState: 'deployed' }),
        outcome({ outcome: 'none', coverageState: 'detection-authored' }),
        outcome({ outcome: 'logged', coverageState: 'telemetry-observed' }),
        outcome({ outcome: 'none', coverageState: 'validated' }),
      ];
      const range = runInputs(run({ source: 'lylat-range:m1', proofScope: 'range', missionId: 'm1', outcomes }));
      expect(range.covered.map(m => [m.qualifier, m.basis, m.strength, m.via ?? null])).toEqual([
        ['range', 'range-deployed', 'full', 'wazuh:9'],
        ['range', 'range-detection-authored', 'full', null],
        ['range', 'range-telemetry-observed', 'partial', null],
      ]);
      // RP-F decision 31: the telemetry-observed row's partial mark is partial by telemetry, never by breadth.
      expect(range.covered.map(m => m.partialCause ?? null)).toEqual([null, null, 'telemetry']);
      expect(range.proof).toEqual([]);
      expect(runInputs(run({ outcomes })).covered).toEqual([]);
      // RP-F decision 35: the telemetry cause carries the row's outcome; no other mark does.
      expect(range.covered.map(m => m.telemetryOutcome ?? null)).toEqual([null, null, 'logged']);
    });

    // RP-F decision 35 (round 7): a telemetry-observed row whose rule alerted or blocked
    // records that outcome on its partial mark, where the mark is produced.
    for (const fired of ['alerted', 'blocked', 'none', 'logged'] as const) {
      it(`a telemetry-observed row with outcome ${fired} records it on the telemetry partial`, () => {
        const outcomes = [outcome({ outcome: fired, detectionRef: 'wazuh:12', coverageState: 'telemetry-observed' })];
        const range = runInputs(run({ source: 'lylat-range:m1', proofScope: 'range', missionId: 'm1', status: 'partial', outcomes }));
        expect(range.covered.map(m => [m.basis, m.strength, m.via, m.partialCause, m.telemetryOutcome]))
          .toEqual([['range-telemetry-observed', 'partial', 'wazuh:12', 'telemetry', fired]]);
      });
    }

    // PR #240 round 1: the telemetry outcome is read from the run's fired set (firedRules),
    // the set the pill and the Proven block count, never from the row alone. Both shapes
    // reach the store through Import JSON (sanitizeRun keeps a lylat-range source and a
    // null detectionRef).
    describe("the telemetry outcome follows the run's fired set (PR #240 round 1)", () => {
      const range = (over: Partial<ValidationRunV2>) =>
        runInputs(run({ source: 'lylat-range:m1', proofScope: 'range', missionId: 'm1', status: 'partial', ...over }));
      const telemetry = (r: ReturnType<typeof runInputs>) => r.covered.filter(m => m.partialCause === 'telemetry');

      it("(a) a 'logged' row whose rule is in detectionsFired reads alerted, as the pill counts it", () => {
        const r = range({
          detectionsFired: ['wazuh:5'],
          outcomes: [outcome({ outcome: 'logged', detectionRef: 'wazuh:5', coverageState: 'telemetry-observed' })],
        });
        expect(firedRules({ detectionsFired: ['wazuh:5'], outcomes: [{ detectionRef: 'wazuh:5', outcome: 'logged' }] })).toEqual(['wazuh:5']);
        expect(telemetry(r).map(m => [m.via, m.telemetryOutcome])).toEqual([['wazuh:5', 'alerted']]);
        expect(r.summary.rulesFired).toBe(1);
        expect(telemetryPartialWords(telemetry(r))).toContain('the rule alerted in this run');
        expect(telemetryPartialWords(telemetry(r))).not.toContain('no detection alerted');
      });

      for (const ref of [null, '', '   ']) {
        it(`(b) an 'alerted' row with detectionRef ${JSON.stringify(ref)} fired nothing the pill counts, so it reads logged`, () => {
          const r = range({ outcomes: [outcome({ outcome: 'alerted', detectionRef: ref, coverageState: 'telemetry-observed' })] });
          expect(r.summary.rulesFired).toBe(0);
          expect(r.proof).toEqual([]);
          expect(telemetry(r).map(m => m.telemetryOutcome)).toEqual(['logged']);
          expect(telemetryPartialWords(telemetry(r))).toContain('no detection alerted');
          expect(telemetryPartialWords(telemetry(r))).not.toContain('the rule alerted');
        });
      }

      it("an 'alerted' row in a run whose attack was blocked reads blocked, as its proof record does", () => {
        const r = range({
          attackResult: 'blocked',
          outcomes: [outcome({ outcome: 'alerted', detectionRef: 'wazuh:12', coverageState: 'telemetry-observed' })],
        });
        expect(r.proof.map(p => [p.detectionRef, p.outcome])).toEqual([['wazuh:12', 'blocked']]);
        expect(telemetry(r).map(m => m.telemetryOutcome)).toEqual(['blocked']);
      });

      it("a 'logged' row whose rule fired only through another row's blocked outcome reads blocked", () => {
        const r = range({
          outcomes: [
            outcome({ outcome: 'blocked', detectionRef: 'wazuh:7', coverageState: 'validated' }),
            outcome({ outcome: 'logged', detectionRef: 'wazuh:7', coverageState: 'telemetry-observed' }),
          ],
        });
        expect(telemetry(r).map(m => m.telemetryOutcome)).toEqual(['blocked']);
      });

      it("a 'none' row whose rule did not fire keeps none; a 'logged' row keeps logged", () => {
        const r = range({
          detectionsFired: ['wazuh:9'],
          outcomes: [
            outcome({ outcome: 'none', detectionRef: 'wazuh:1', coverageState: 'telemetry-observed' }),
            outcome({ outcome: 'logged', detectionRef: 'wazuh:2', coverageState: 'telemetry-observed' }),
          ],
        });
        expect(telemetry(r).map(m => m.telemetryOutcome)).toEqual(['none', 'logged']);
      });
    });

    it('carries the mission id onto range proof', () => {
      const r = runInputs(run({
        source: 'lylat-range:m1', proofScope: 'range', missionId: 'm1',
        outcomes: [outcome({ outcome: 'alerted', detectionRef: 'wazuh:990003', coverageState: 'validated' })],
      }));
      expect(r.proof).toEqual([jasmine.objectContaining({ scope: 'range', missionId: 'm1', source: 'lylat-range:m1' })]);
    });
  });

  describe('matching and technique marks', () => {
    it('matches by runMatches: a ref, or the bare id when the ref is null', () => {
      const runs = [run({ id: 'a' }), run({ id: 'b', techniqueRef: null, techniqueId: 'T1003' }), run({ id: 'c', techniqueRef: null, techniqueId: 'T9999' })];
      const m = matchToTechniques(runs, r => r, domain.techniques, 'enterprise', identity);
      expect(m.get(tech('T1003').id)!.map(r => r.id)).toEqual(['a', 'b']);
      expect([...m.values()].flat().some(r => r.id === 'c')).toBeFalse();
    });

    it('turns technique marks into technique-confirmed marks', () => {
      const rec: TechniqueMarkRecord = {
        ref: 'attack/enterprise/T1003@19.2', via: 'M1026', status: 'implemented', source: 'manual',
        domain: 'enterprise', attackVersion: '19.2', createdAt: 'x', updatedAt: '2026-09-01T00:00:00.000Z',
      };
      expect(techniqueMarkToCovered(rec)).toEqual({
        qualifier: 'self-attested', basis: 'technique-confirmed', strength: 'full', source: 'manual',
        at: '2026-09-01T00:00:00.000Z', via: 'M1026',
      });
      expect(techniqueMarkToCovered({ ...rec, status: 'planned' })!.strength).toBe('planned');
      expect(techniqueMarkToCovered({ ...rec, status: 'not-started' })).toBeNull();
      expect(markKey(rec)).toEqual({ techniqueRef: rec.ref, techniqueId: 'T1003' });
    });
  });

  describe('implView', () => {
    const view = (t: Technique, impl: Map<string, ImplStatus>, statuses: ImplStatus[] = [], threshold = 15) =>
      implView(t, impl, domain, threshold, statuses);

    it('guards the status fold: M1026 implemented is partial via M1026, M1047 is not', () => {
      const t = domain.techniquesByMitigation.get(mit('M1026').id)!.find(x => !domain.techniquesByMitigation.get(mit('M1047').id)!.includes(x))!;
      expect(view(t, new Map([[mit('M1026').id, 'implemented']]))).toEqual({ status: 'implemented', partialVia: 'M1026' });
      const u = domain.techniquesByMitigation.get(mit('M1047').id)![0];
      expect(view(u, new Map([[mit('M1047').id, 'implemented']]))).toEqual({ status: 'implemented', partialVia: null });
      expect(view(t, new Map([[mit('M1026').id, 'implemented']]), ['implemented'])).toEqual({ status: 'implemented', partialVia: null });
      expect(view(t, new Map([[mit('M1026').id, 'implemented']]), [], 20)).toEqual({ status: 'implemented', partialVia: null });
    });

    it('otherwise returns the best remaining status, or null', () => {
      const t = domain.techniquesByMitigation.get(mit('M1026').id)![0];
      expect(view(t, new Map())).toEqual({ status: null, partialVia: null });
      expect(view(t, new Map([[mit('M1026').id, 'planned']]), ['in-progress'])).toEqual({ status: 'in-progress', partialVia: null });
      expect(view(t, new Map([[mit('M1026').id, 'not-started']]))).toEqual({ status: 'not-started', partialVia: null });
    });
  });
});
