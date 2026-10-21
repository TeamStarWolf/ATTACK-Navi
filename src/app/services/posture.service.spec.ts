// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// PostureService (Phase 2 design §3 P2-05), on the lens fixture
// (src/testing/fixtures/enterprise-lens.stix.json) parsed by the real
// DataService, with the harness's deterministic Known-signal stubs and
// POSTURE_TODAY pinned to 2026-10-01 (§7, R14).
//
// Precondition (§1.17, R22): the loaded techniquesByMitigation counts are
// M1047 = 13 and M1026 = 16. If loading ever changes them, every spec that
// uses them fails with a message saying so, and the [AC] specs must move to
// new ids.
import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import type { Domain } from '../models/domain';
import type { Mitigation } from '../models/mitigation';
import type { Technique } from '../models/technique';
import type { PostureState } from '../models/posture/posture.types';
import { POSTURE_TODAY, createPostureToday, postureDay } from '../models/posture/posture-today';
import { THREAT_WEIGHT_PROVIDER, allGroupsWeight } from '../models/posture/threat-weight';
import { ThreatProfileService } from './threat-profile.service';
import { type TechniqueRefKey, refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { type AttackDomain, DataService } from './data.service';
import { ControlsService } from './controls.service';
import { EnrichmentService } from './enrichment.service';
import { EventLoggingService } from './event-logging.service';
import { ImplementationService } from './implementation.service';
import { OwnerDataService } from './owner-data.service';
import { PostureService } from './posture.service';
import { SettingsService } from './settings.service';
import { TechniqueMarksService } from './technique-marks.service';
import { TelemetryCoverageService, telemetryKey } from './telemetry-coverage.service';
import { VALIDATION_RUNS_V1_KEY, VALIDATION_RUNS_V2_KEY, ValidationService } from './validation.service';
import { parseFixtureDomain, resetBrowserState, signalStubProviders } from '../testing/lens-harness';

const TODAY = new Date('2026-10-01T00:00:00.000Z');
const daysBefore = (n: number) => new Date(TODAY.getTime() - n * 86_400_000).toISOString();

/** A minimal Domain holding only the given techniques (the ICS and F3 parity cases). */
function tinyDomain(name: string, attackVersion: string, ids: readonly string[]): Domain {
  const techniques: Technique[] = ids.map(attackId => ({
    id: `attack-pattern--${name}-${attackId}`, attackId, name: attackId, description: '', url: '',
    tacticShortnames: [], isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  }));
  return {
    name, attackVersion, attackModified: '', tactics: [], techniques, mitigations: [], tacticColumns: [],
    mitigationsByTechnique: new Map(), techniquesByMitigation: new Map(), maxMitigationCount: 0,
    groups: [], groupsByTechnique: new Map(), techniquesByGroup: new Map(),
    software: [], softwareByTechnique: new Map(), techniquesBySoftware: new Map(), proceduresByTechnique: new Map(),
    dataSources: [], dataComponents: [], techniquesByDataComponent: new Map(), dataComponentsByTechnique: new Map(),
    campaigns: [], campaignsByTechnique: new Map(), techniquesByCampaign: new Map(),
    softwareByGroup: new Map(), groupsBySoftware: new Map(), softwareByCampaign: new Map(), campaignsByGroup: new Map(),
    detectionNotesByTechnique: new Map(), supersededBy: new Map(), retiredNames: new Map(),
  };
}

describe('PostureService (P2-05, E2.1-c)', () => {
  let domain: Domain;
  let posture: PostureService;

  /** Load a domain the way DataService publishes one. */
  function load(d: Domain, id: AttackDomain): void {
    const ds = TestBed.inject(DataService) as unknown as {
      attackDomain: AttackDomain; currentDomain$: { next(v: AttackDomain): void }; domainSubject: { next(v: Domain | null): void };
    };
    ds.attackDomain = id;
    ds.currentDomain$.next(id);
    ds.domainSubject.next(d);
  }

  /** Configure TestBed (after `seed` writes any storage) and load the fixture as Enterprise. */
  function boot(seed?: () => void): void {
    resetBrowserState();
    seed?.();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(),
        ...signalStubProviders(),
        { provide: POSTURE_TODAY, useValue: signal(TODAY) },
      ],
    });
    load(domain, 'enterprise');
    posture = TestBed.inject(PostureService);
  }

  afterEach(() => resetBrowserState());

  const tech = (attackId: string): Technique => domain.techniques.find(t => t.attackId === attackId)!;
  const keyOf = (t: Pick<Technique, 'attackId'>): TechniqueRefKey => techniqueRefKey(refForTechnique(t, 'enterprise', '19.2'));
  const stateOf = (t: Technique): PostureState => posture.states().get(keyOf(t))!;

  /** The loaded mitigation, asserting its breadth loudly (§1.17 precondition). */
  function mitigation(attackId: string, expected: number): Mitigation {
    const m = domain.mitigations.find(x => x.attackId === attackId);
    const n = m ? domain.techniquesByMitigation.get(m.id)?.length : undefined;
    if (!m || n !== expected) {
      throw new Error(
        `Lens fixture precondition failed: techniquesByMitigation(${attackId}) is ${n}, expected ${expected} ` +
        '(Phase 2 design §1.17). The [AC] specs must pick new mitigation ids.',
      );
    }
    return m;
  }
  const refsOf = (m: Mitigation): TechniqueRefKey[] => domain.techniquesByMitigation.get(m.id)!.map(keyOf).sort();

  const snapshot = () => new Map([...posture.states()].map(([k, s]) => [k, JSON.stringify(s)]));
  function changed(before: Map<TechniqueRefKey, string>): TechniqueRefKey[] {
    return [...posture.states()].filter(([k, s]) => before.get(k) !== JSON.stringify(s)).map(([k]) => k).sort();
  }

  describe('on the lens fixture', () => {
    beforeEach(() => boot());

    it('holds one state per technique of the loaded domain, keyed by TechniqueRefKey', () => {
      expect(domain.attackVersion).toBe('19.2');
      expect(posture.states().size).toBe(domain.techniques.length);
      expect(stateOf(tech('T1003')).ref).toBe('attack/enterprise/T1003@19.2');
      expect(posture.ownerWords()).toBeFalse();
      expect(posture.unmatched()).toEqual([]);
    });

    it('precondition: M1047 maps 13 techniques and M1026 maps 16', () => {
      expect(() => mitigation('M1047', 13)).not.toThrow();
      expect(() => mitigation('M1026', 16)).not.toThrow();
      expect(() => mitigation('M1026', 15)).toThrowError(/precondition failed/);
    });

    it('[AC] marking a mitigation mapped to <=15 techniques implemented changes exactly those techniques', () => {
      const m1047 = mitigation('M1047', 13);
      const before = snapshot();
      TestBed.inject(ImplementationService).setStatus(m1047.id, 'implemented');
      const diff = changed(before);
      expect(diff).toEqual(refsOf(m1047));
      expect(diff.length).toBe(13);
      for (const k of diff) {
        const s = posture.states().get(k)!;
        expect(s.bucket).withContext(k).toBe('covered');
        expect(s.qualifiers).withContext(k).toEqual(['self-attested']);
      }
    });

    it('[AC] marking a broader mitigation produces partial marks only', () => {
      const m1026 = mitigation('M1026', 16);
      const before = snapshot();
      TestBed.inject(ImplementationService).setStatus(m1026.id, 'implemented');
      const diff = changed(before);
      expect(diff).toEqual(refsOf(m1026));
      expect(diff.length).toBe(16);
      for (const k of diff) {
        const s = posture.states().get(k)!;
        expect(s.bucket).withContext(k).toBe('partial');
        expect(s.subStates).withContext(k).toContain('partial');
      }
      expect([...posture.states().values()].some(s => s.bucket === 'covered')).toBeFalse();
    });

    it('confirming one technique through TechniqueMarksService makes only that ref covered', () => {
      const t = tech('T1593');
      const before = snapshot();
      expect(TestBed.inject(TechniqueMarksService).confirm(keyOf(t))).toBeTrue();
      expect(changed(before)).toEqual([keyOf(t)]);
      expect(stateOf(t).bucket).toBe('covered');
      expect(stateOf(t).covered.map(m => [m.basis, m.source])).toEqual([['technique-confirmed', 'manual']]);
    });

    it('threshold setting 20 makes M1026 full, and the change recomputes through settings', () => {
      const m1026 = mitigation('M1026', 16);
      TestBed.inject(ImplementationService).setStatus(m1026.id, 'implemented');
      expect(refsOf(m1026).every(k => posture.states().get(k)!.bucket === 'partial')).toBeTrue();
      const settings = TestBed.inject(SettingsService);
      settings.update({ posture: { ...settings.current.posture, mitigationBreadthThreshold: 20 } });
      for (const k of refsOf(m1026)) expect(posture.states().get(k)!.bucket).withContext(k).toBe('covered');
    });

    it("wizard technique keys become 'technique-confirmed' marks from 'wizard'", () => {
      const t = tech('T1593');
      TestBed.inject(ImplementationService).setStatus(t.id, 'implemented');
      expect(stateOf(t).bucket).toBe('covered');
      expect(stateOf(t).covered).toEqual([{ qualifier: 'self-attested', basis: 'technique-confirmed', strength: 'full', source: 'wizard' }]);
      expect(posture.unmatched()).toEqual([]);
    });

    it('junk keys appear in unmatched() and change no state', () => {
      const before = snapshot();
      const impl = TestBed.inject(ImplementationService);
      impl.setStatus('M1036', 'implemented');
      impl.setStatus('not-a-stix-id', 'planned');
      expect(posture.unmatched().map(u => [u.key, u.store])).toEqual([['M1036', 'impl'], ['not-a-stix-id', 'impl']]);
      expect(changed(before)).toEqual([]);
      expect(impl.getStatus('M1036')).toBe('implemented');
    });

    it('an unmapped telemetry technique is not covered; a mapped one with every key configured is', () => {
      const telemetry = TestBed.inject(TelemetryCoverageService);
      for (const row of telemetry.buildMatrix()) telemetry.setStatus(row.key, true);
      const unmapped = tech('T1593');
      expect(TestBed.inject(EventLoggingService).getLoggingConfig(unmapped.attackId)).toEqual([]);
      expect(stateOf(unmapped).covered).toEqual([]);
      expect(['none', 'known']).toContain(stateOf(unmapped).bucket);
      const mapped = tech('T1112');
      expect(stateOf(mapped).bucket).toBe('covered');
      expect(stateOf(mapped).covered.map(m => m.basis)).toEqual(['telemetry-configured']);
    });

    it('a mapped technique with only some keys configured is not covered', () => {
      const t = tech('T1003.001');
      const keys = TestBed.inject(EventLoggingService).getLoggingConfig(t.attackId).map(c => telemetryKey(c.source, c.eventId));
      expect(keys.length).toBeGreaterThan(1);
      TestBed.inject(TelemetryCoverageService).setStatus(keys[0], true);
      expect(stateOf(t).covered).toEqual([]);
    });

    it('[AC] every Covered badge names its qualifier: every covered or partial state has non-empty qualifiers', () => {
      const impl = TestBed.inject(ImplementationService);
      impl.setStatus(mitigation('M1047', 13).id, 'implemented');
      impl.setStatus(mitigation('M1026', 16).id, 'implemented');
      impl.setStatus(tech('T1593').id, 'implemented');
      TestBed.inject(ControlsService).addControl({
        name: 'c', framework: 'Custom', controlRef: 'c', description: '', mitigationIds: [domain.mitigations[0].id], status: 'implemented',
      });
      const telemetry = TestBed.inject(TelemetryCoverageService);
      for (const row of telemetry.buildMatrix()) telemetry.setStatus(row.key, true);
      TestBed.inject(ValidationService).importRows([{
        id: 'range-1', techniqueId: 'T1597', runDate: daysBefore(10), status: 'passed', attackResult: 'executed',
        outcomes: [{ detectionRef: 'wazuh:1', outcome: 'none', coverageState: 'deployed' }],
      } as never], 'lylat-range:m1');
      const shown = [...posture.states().values()].filter(s => s.bucket === 'covered' || s.bucket === 'partial');
      expect(shown.filter(s => s.bucket === 'covered').length).toBeGreaterThan(0);
      expect(shown.filter(s => s.bucket === 'partial').length).toBeGreaterThan(0);
      expect(stateOf(tech('T1597')).qualifiers).toContain('range');
      for (const s of shown) expect(s.qualifiers.length).withContext(s.ref).toBeGreaterThan(0);
    });

    it("a blocked own run without a detection is bucket 'covered' with basis 'own-run-blocked', never 'proven'", () => {
      const t = tech('T1593');
      TestBed.inject(ValidationService).record({
        techniqueId: t.attackId, techniqueName: t.name, operator: '', runDate: daysBefore(3),
        telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '', attackResult: 'blocked',
        detectionsExpected: [], detectionsFired: [], responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '',
      });
      const s = stateOf(t);
      expect(s.bucket).toBe('covered');
      expect(s.rung).toBe('covered');
      expect(s.proof).toEqual([]);
      expect(s.covered.map(m => [m.qualifier, m.basis, m.strength])).toEqual([['self-attested', 'own-run-blocked', 'full']]);
    });

    it('a run with a named detection reaches the top rung, and expiringSoon counts a proof near its window', () => {
      const validation = TestBed.inject(ValidationService);
      validation.importJson(JSON.stringify({ runs: [
        { id: 'p1', techniqueId: 'T1593', runDate: daysBefore(85), status: 'passed', attackResult: 'executed', detectionsFired: ['sigma:a'] },
        { id: 'p2', techniqueId: 'T1597', runDate: daysBefore(10), status: 'passed', attackResult: 'executed', detectionsFired: ['sigma:b'] },
        { id: 'p3', techniqueId: 'T1589', runDate: daysBefore(120), status: 'passed', attackResult: 'executed', detectionsFired: ['sigma:c'] },
      ] }));
      expect(stateOf(tech('T1593'))).toEqual(jasmine.objectContaining({ rung: 'proven', bucket: 'proven', proofScope: 'own-run', proofAge: 85 }));
      expect(stateOf(tech('T1589')).bucket).toBe('stale');
      expect(posture.expiringSoon()).toBe(1);
      expect(posture.ownerWords()).toBeTrue();
    });

    it('R16: one not-reproducible run moves assessable by -1 and leaves total, mapped and pct unchanged', () => {
      const before = posture.rollup();
      const known = TestBed.inject(EnrichmentService).mappedRollup(domain);
      expect([before.overall.total, before.overall.mapped, before.overall.pct]).toEqual([known.overall.total, known.overall.mapped, known.overall.pct]);
      TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
        { id: 'nr1', techniqueId: 'T1593', runDate: daysBefore(5), status: 'not-reproducible', attackResult: 'executed' },
      ] }));
      const after = posture.rollup();
      expect(after.overall.assessable).toBe(before.overall.assessable - 1);
      expect(after.overall.notReproducible).toBe(1);
      expect([after.overall.total, after.overall.mapped, after.overall.pct]).toEqual([before.overall.total, before.overall.mapped, before.overall.pct]);
      expect(after.byTactic.map(r => [r.tacticId, r.total, r.mapped, r.pct])).toEqual(before.byTactic.map(r => [r.tacticId, r.total, r.mapped, r.pct]));
      expect(stateOf(tech('T1593')).excluded).toBeTrue();
    });

    it('rollup keeps the Known numbers of mappedRollup, with and without sub-techniques', () => {
      const enrichment = TestBed.inject(EnrichmentService);
      for (const opts of [{}, { includeSubtechniques: true }]) {
        const known = enrichment.mappedRollup(domain, opts);
        const r = posture.rollup(opts);
        expect([r.overall.total, r.overall.mapped, r.overall.pct]).toEqual([known.overall.total, known.overall.mapped, known.overall.pct]);
        expect(r.overall.none + r.overall.known + r.overall.partial + r.overall.covered + r.overall.proven + r.overall.stale).toBe(r.overall.total);
        expect(r.byTactic.map(b => [b.tacticId, b.shortname, b.total, b.mapped, b.pct]))
          .toEqual(known.byTactic.map(b => [b.tacticId, b.shortname, b.total, b.mapped, b.pct]));
      }
    });

    it('tallyFor matches the states over the same techniques', () => {
      TestBed.inject(ImplementationService).setStatus(mitigation('M1047', 13).id, 'implemented');
      const t = posture.tallyFor(domain.techniques);
      expect(t.total).toBe(domain.techniques.length);
      expect(t.covered).toBe([...posture.states().values()].filter(s => s.bucket === 'covered').length);
      const outside = tinyDomain('elsewhere', '19.2', ['T9999']).techniques[0];
      expect(posture.stateFor(outside).bucket).toBe('none');
    });

    it('implViewFor: M1026 is implemented, partial via M1026; M1047 and a confirmed technique are not partial', () => {
      const m1026 = mitigation('M1026', 16);
      const m1047 = mitigation('M1047', 13);
      const impl = TestBed.inject(ImplementationService);
      impl.setStatus(m1026.id, 'implemented');
      const only1026 = domain.techniquesByMitigation.get(m1026.id)!
        .filter(t => !domain.techniquesByMitigation.get(m1047.id)!.includes(t));
      for (const t of only1026) {
        expect(posture.implViewFor(t)).withContext(t.attackId).toEqual({ status: 'implemented', partialVia: 'M1026' });
      }
      impl.setStatus(m1047.id, 'implemented');
      for (const t of domain.techniquesByMitigation.get(m1047.id)!) {
        expect(posture.implViewFor(t)).withContext(t.attackId).toEqual({ status: 'implemented', partialVia: null });
      }
      const confirmed = only1026[0];
      TestBed.inject(TechniqueMarksService).confirm(keyOf(confirmed));
      expect(posture.implViewFor(confirmed)).toEqual({ status: 'implemented', partialVia: null });
      const unmitigated = domain.techniques.find(t => (domain.mitigationsByTechnique.get(t.id) ?? []).length === 0)!;
      expect(posture.implViewFor(unmitigated)).toEqual({ status: null, partialVia: null });
    });

    it('owner words: controls-only (one implemented control behind M1047) shows words, and tallyFor matches the states', () => {
      const m1047 = mitigation('M1047', 13);
      TestBed.inject(ControlsService).addControl({
        name: 'EDR policy', framework: 'Custom', controlRef: 'c1', description: '', mitigationIds: [m1047.id], status: 'implemented',
      });
      expect(posture.ownerWords()).toBeTrue();
      const states = [...posture.states().values()];
      const tally = posture.tallyFor(domain.techniques);
      expect(tally.covered).toBe(states.filter(s => s.bucket === 'covered').length);
      expect(tally.covered).toBe(13);
      expect(posture.ownerData()).toEqual({ implementation: 0, validation: 0, stack: 0 });
    });

    it('owner words: planned-only shows none', () => {
      TestBed.inject(ImplementationService).setStatus(mitigation('M1047', 13).id, 'planned');
      expect(posture.ownerWords()).toBeFalse();
      expect([...posture.states().values()].filter(s => s.subStates.includes('planned')).length).toBe(13);
      expect(posture.ownerData().implementation).toBe(1);
    });

    it('takes the threat weight from THREAT_WEIGHT_PROVIDER (all groups by default) and exposure on Enterprise', () => {
      const weighted = domain.techniques.find(t => (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0)!;
      expect(stateOf(weighted).threatWeight).toBe(allGroupsWeight(domain, weighted.id));
      expect(TestBed.inject(THREAT_WEIGHT_PROVIDER).weight(weighted.id)).toBe(stateOf(weighted).threatWeight);
      expect([...posture.states().values()].some(s => s.exposureWeight > 0)).toBeTrue();
    });

    it('bridges states to states$', () => {
      const seen: number[] = [];
      const sub = posture.states$.subscribe(m => seen.push(m.size));
      TestBed.tick();
      sub.unsubscribe();
      expect(seen.at(-1)).toBe(domain.techniques.length);
    });

    it('holds no state while no domain is loaded', () => {
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(v: null): void } }).domainSubject.next(null);
      expect(posture.states().size).toBe(0);
      expect(posture.rollup().overall.total).toBe(0);
      expect(posture.implViewFor(tech('T1003'))).toEqual({ status: null, partialVia: null });
      TestBed.inject(ImplementationService).setStatus('M1036', 'implemented');
      expect(posture.unmatched().map(u => u.key)).withContext('classification needs no domain').toEqual(['M1036']);
    });
  });

  describe('R6: runs light the technique of the loaded domain (runMatches)', () => {
    it('an ICS run migrated with techniqueRef null lights T0807 after ICS loads', () => {
      boot(() => localStorage.setItem(VALIDATION_RUNS_V1_KEY, JSON.stringify([{
        id: 'ics-1', techniqueId: 'T0807', runDate: daysBefore(20), status: 'passed', attackResult: 'executed',
        detectionsExpected: ['dragos:1'], detectionsFired: ['dragos:1'],
      }])));
      const run = TestBed.inject(ValidationService).all.find(r => r.id === 'ics-1')!;
      expect(run.techniqueRef).toBeNull();
      expect([...posture.states().values()].some(s => s.proof.length > 0)).toBeFalse();
      const ics = tinyDomain('ics', '19.2', ['T0807', 'T0800']);
      load(ics, 'ics');
      const lit = posture.states().get('attack/ics/T0807@19.2')!;
      expect(lit).toEqual(jasmine.objectContaining({ rung: 'proven', bucket: 'proven', proofScope: 'own-run' }));
      expect(posture.states().get('attack/ics/T0800@19.2')!.proof).toEqual([]);
      expect(['none', 'known']).toContain(posture.states().get('attack/ics/T0800@19.2')!.bucket);
      expect(posture.states().size).toBe(2);
    });

    it("an Enterprise T1110 run lights F3's T1110 (F3 T-ids are Enterprise ids); F-ids stay unlit", () => {
      // Record: import the run through the store, which persists it to navi.v2.validation-runs.
      boot();
      TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [{
        id: 'ent-1', techniqueId: 'T1110', techniqueRef: 'attack/enterprise/T1110@19.2', domain: 'enterprise', attackVersion: '19.2',
        runDate: daysBefore(20), status: 'passed', attackResult: 'executed', detectionsFired: ['sigma:brute'],
      }] }));
      const persisted = localStorage.getItem(VALIDATION_RUNS_V2_KEY);
      expect(persisted).withContext('the import persisted the run').not.toBeNull();
      expect(persisted).toContain('attack/enterprise/T1110@19.2');

      // Reload: a fresh injector whose ValidationService reads the run back from storage alone.
      TestBed.resetTestingModule();
      boot(() => localStorage.setItem(VALIDATION_RUNS_V2_KEY, persisted!));
      const reread = TestBed.inject(ValidationService).all.find(r => r.id === 'ent-1')!;
      expect(reread).withContext('the run was re-read from navi.v2.validation-runs').toBeDefined();
      expect(reread.techniqueRef).toBe('attack/enterprise/T1110@19.2');
      expect(reread.techniqueId).toBe('T1110');

      // Look up: F3 loads after the reload and the stored run matches its T1110 through runMatches.
      const f3 = tinyDomain('f3', '1.0', ['T1110', 'F1001']);
      load(f3, 'f3');
      expect(posture.states().get('f3/f3/T1110@1.0')).toEqual(jasmine.objectContaining({ rung: 'proven', proofScope: 'own-run' }));
      expect(posture.states().get('f3/f3/F1001@1.0')!.proof).toEqual([]);
      expect(['none', 'known']).toContain(posture.states().get('f3/f3/F1001@1.0')!.bucket);
      expect(posture.states().get('f3/f3/T1110@1.0')!.exposureWeight).toBe(0);
    });
  });

  describe('POSTURE_TODAY (§7)', () => {
    it('has day granularity and moves only when the day changes', () => {
      let now = new Date('2026-10-01T23:30:00.000Z');
      const { today, refresh } = createPostureToday(() => now);
      const first = today();
      expect(first.toISOString()).toBe('2026-10-01T00:00:00.000Z');
      now = new Date('2026-10-01T23:59:00.000Z');
      refresh();
      expect(today()).toBe(first);
      now = new Date('2026-10-02T00:30:00.000Z');
      refresh();
      expect(today().toISOString()).toBe('2026-10-02T00:00:00.000Z');
    });

    it('defaults to the current UTC day when not pinned', () => {
      TestBed.configureTestingModule({});
      expect(TestBed.inject(POSTURE_TODAY)().getTime()).toBe(postureDay(new Date()).getTime());
    });
  });

  describe('owner data stays domain-free (D4)', () => {
    it('does not count controls', () => {
      boot();
      const seen: boolean[] = [];
      TestBed.inject(OwnerDataService).hasOwnerData$.subscribe(v => seen.push(v));
      TestBed.inject(ControlsService).addControl({
        name: 'c', framework: 'Custom', controlRef: 'c', description: '', mitigationIds: [mitigation('M1047', 13).id], status: 'implemented',
      });
      expect(seen).toEqual([false]);
      expect(posture.ownerWords()).toBeTrue();
    });
  });

  // P2-10 reactive seam: with the real ThreatProfileService bound as the provider,
  // a profile change must reach states().threatWeight in one change-detection pass.
  describe('threat weight tracks the bound profile (P2-10)', () => {
    let threatProfile: ThreatProfileService;
    beforeEach(() => {
      resetBrowserState();
      domain = parseFixtureDomain();
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(withXhr()), provideHttpClientTesting(),
          ...signalStubProviders(),
          { provide: POSTURE_TODAY, useValue: signal(TODAY) },
          { provide: THREAT_WEIGHT_PROVIDER, useExisting: ThreatProfileService },
        ],
      });
      load(domain, 'enterprise');
      threatProfile = TestBed.inject(ThreatProfileService);
      posture = TestBed.inject(PostureService);
    });

    it('setSource reaches states().threatWeight in one change-detection pass', () => {
      const g = domain.groups[0];
      const used = (domain.techniquesByGroup.get(g.id) ?? []).find(t => !t.isSubtechnique);
      expect(used).withContext('fixture group 0 uses a parent technique').toBeTruthy();
      void stateOf(used!).threatWeight;   // memoize the default-profile compute
      threatProfile.setSource({ kind: 'groups', ids: [g.id] });
      // states() recomputed from the narrowed profile: exactly one actor (g) uses `used`.
      expect(stateOf(used!).threatWeight).toBe(1);
      expect(threatProfile.weight(used!.id)).toBe(1);
    });
  });

  // Range-import posture (P2-20, E2.5-a): importRangeContract must drive the same
  // reactive signals a manual record() drives, and the posture layer counts one
  // state per distinct technique (the per-tactic repetition is a matrix concern).
  describe('range import (P2-20)', () => {
    const LYLAT_IDS = ['T1558.003', 'T1087.002', 'T1078.002', 'T1059.001', 'T1003.001', 'T1021.002'];
    let validation: ValidationService;

    /** Boot PostureService over a tiny Enterprise domain of the fixture's techniques. */
    function bootRange(today: Date): void {
      resetBrowserState();
      domain = tinyDomain('ent', '19.2', LYLAT_IDS);
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(withXhr()), provideHttpClientTesting(),
          ...signalStubProviders(),
          { provide: POSTURE_TODAY, useValue: signal(today) },
        ],
      });
      load(domain, 'enterprise');
      validation = TestBed.inject(ValidationService);
      posture = TestBed.inject(PostureService);
    }

    /** A valid contract over the given techniques, each validated `ageDays` before `today`. */
    function contractFor(today: Date, rows: readonly { id: string; ageDays: number }[]): string {
      const dateOf = (ageDays: number) => new Date(today.getTime() - ageDays * 86_400_000).toISOString().slice(0, 10);
      return JSON.stringify({
        schema: 'lylat-validated-detections/1', range_build_ref: 'a1b2c3d', generated_at: today.toISOString(),
        rows: rows.map((r, i) => ({
          mission_id: 'SYNTH-MISSION-A',
          technique_ref: { domain: 'enterprise', id: r.id, attack_version: '19.2' },
          detection_ref: `wazuh:${990001 + i}`, coverage_state: 'validated', outcome: 'alerted',
          negative_control: 'detection-only', validated_at: dateOf(r.ageDays), evidence_ref: `SYNTH-MISSION-A-step${i}`,
        })),
      });
    }

    // Item 1: the Proven lens/posture update in-session, no reload — the import path
    // emits on the same runs$ a manual record() does, and PostureService tracks it.
    it('[AC] importRangeContract makes a technique read proven in the same session', () => {
      const today = new Date('2026-10-21T00:00:00.000Z');
      bootRange(today);
      const key = keyOf({ attackId: 'T1059.001' });
      expect(posture.states().get(key)!.bucket).not.toBe('proven');

      const res = validation.importRangeContract(contractFor(today, LYLAT_IDS.map(id => ({ id, ageDays: 2 }))));
      expect(res.ok).toBeTrue();

      // Same posture instance — no rebuild/reload. states() recomputed off runs$.
      const s = posture.states().get(key)!;
      expect(s.bucket).toBe('proven');
      expect(s.proofScope).toBe('range');
    });

    // Items 6/12 [AC]: one posture state per DISTINCT technique (never per tactic),
    // fresh range proofs are proven and a proof aged past the 90-day range window
    // is stale — counted under the pinned POSTURE_TODAY.
    it('[AC] counts distinct range-proof techniques: five proven (fresh), one stale (aged)', () => {
      const today = new Date('2026-10-21T00:00:00.000Z');
      bootRange(today);
      const ages = LYLAT_IDS.map((id, i) => ({ id, ageDays: i === 0 ? 120 : 10 })); // one past the 90-day window
      expect(validation.importRangeContract(contractFor(today, ages)).ok).toBeTrue();

      const rangeStates = [...posture.states().values()].filter(s => s.proofScope === 'range');
      expect(rangeStates.length).toBe(6); // one per distinct technique
      expect(rangeStates.filter(s => s.bucket === 'proven').length).toBe(5);
      expect(rangeStates.filter(s => s.bucket === 'stale').length).toBe(1);
    });
  });
});
