// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { EnrichmentService, mappedPct } from './enrichment.service';
import { SigmaService } from './sigma.service';
import { CARService } from './car.service';
import { AtomicService } from './atomic.service';
import { D3fendService } from './d3fend.service';
import { NistMappingService } from './nist-mapping.service';
import { CriProfileService } from './cri-profile.service';
import { CisControlsService } from './cis-controls.service';
import { CsaCcmService } from './csa-ccm.service';
import { M365ControlsService } from './m365-controls.service';
import { AttackCveService } from './attack-cve.service';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';

/** Mutable per-attackId fixtures the mocks read from. */
const counts = {
  sigma: new Map<string, number>(),
  car: new Map<string, number>(),
  atomic: new Map<string, number>(),
  d3fend: new Map<string, number>(),
  nist: new Map<string, number>(),
  cri: new Map<string, number>(),
  cis: new Map<string, number>(),
  csa: new Map<string, number>(),
  m365: new Map<string, number>(),
  cve: new Map<string, number>(),
};

function resetCounts(): void {
  Object.values(counts).forEach(m => m.clear());
}

function arr(n: number): unknown[] {
  return Array.from({ length: n }, (_, i) => i);
}

function tech(attackId: string, id: string, mitigationCount = 0): Technique {
  return { attackId, id, mitigationCount } as unknown as Technique;
}

function emptyDomain(): Domain {
  return {
    groupsByTechnique: new Map(),
    softwareByTechnique: new Map(),
    campaignsByTechnique: new Map(),
    mitigationsByTechnique: new Map(),
  } as unknown as Domain;
}

describe('EnrichmentService', () => {
  let service: EnrichmentService;
  let domain: Domain;

  beforeEach(() => {
    resetCounts();
    domain = emptyDomain();
    TestBed.configureTestingModule({
      providers: [
        { provide: SigmaService, useValue: { getRuleCount: (id: string) => counts.sigma.get(id) ?? 0 } },
        { provide: CARService, useValue: { getLiveCount: (id: string) => counts.car.get(id) ?? 0 } },
        { provide: AtomicService, useValue: { getTestCount: (id: string) => counts.atomic.get(id) ?? 0 } },
        { provide: D3fendService, useValue: { getCountermeasures: (id: string) => arr(counts.d3fend.get(id) ?? 0) } },
        { provide: NistMappingService, useValue: { getControlCount: (id: string) => counts.nist.get(id) ?? 0 } },
        { provide: CriProfileService, useValue: { getControlCount: (id: string) => counts.cri.get(id) ?? 0 } },
        { provide: CisControlsService, useValue: { getControlCount: (id: string) => counts.cis.get(id) ?? 0 } },
        { provide: CsaCcmService, useValue: { getControlCount: (id: string) => counts.csa.get(id) ?? 0 } },
        { provide: M365ControlsService, useValue: { getControlCount: (id: string) => counts.m365.get(id) ?? 0 } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: (id: string) => arr(counts.cve.get(id) ?? 0) } },
      ],
    });
    service = TestBed.inject(EnrichmentService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('treats a technique with zero of every signal as NOT enriched', () => {
    expect(service.isEnriched(tech('T1000', 's-1000'), domain)).toBe(false);
  });

  it('counts a mitigation-only technique as enriched', () => {
    expect(service.isEnriched(tech('T1001', 's-1001', 2), domain)).toBe(true);
  });

  it('counts a detection-only (no mitigation) technique as enriched', () => {
    counts.sigma.set('T1002', 3);
    expect(service.isEnriched(tech('T1002', 's-1002', 0), domain)).toBe(true);
  });

  it('counts a control-only technique as enriched', () => {
    counts.cis.set('T1003', 1);
    expect(service.isEnriched(tech('T1003', 's-1003', 0), domain)).toBe(true);
  });

  it('counts a threat-intel-only technique as enriched', () => {
    const t = tech('T1004', 's-1004', 0);
    domain.groupsByTechnique.set('s-1004', arr(2) as never);
    expect(service.isEnriched(t, domain)).toBe(true);
  });

  it('counts a CVE-only technique as enriched', () => {
    counts.cve.set('T1005', 1);
    expect(service.isEnriched(tech('T1005', 's-1005', 0), domain)).toBe(true);
  });

  it('hasDefensiveSignal excludes atomic / threat-intel / cve', () => {
    counts.atomic.set('T1006', 5);
    counts.cve.set('T1006', 5);
    const t = tech('T1006', 's-1006', 0);
    domain.groupsByTechnique.set('s-1006', arr(3) as never);
    // Enriched (atomic + cve + threat-intel) but NOT defended.
    expect(service.isEnriched(t, domain)).toBe(true);
    expect(service.hasDefensiveSignal(t, domain)).toBe(false);
    // Add a real control → now defended.
    counts.nist.set('T1006', 1);
    expect(service.hasDefensiveSignal(t, domain)).toBe(true);
  });

  it('totals + coverage aggregate the enriched fraction, not the mitigation fraction', () => {
    counts.sigma.set('T2', 1);   // detection only
    counts.cis.set('T3', 1);     // control only
    const techs = [
      tech('T1', 's1', 1),  // mitigation
      tech('T2', 's2', 0),  // detection
      tech('T3', 's3', 0),  // control
      tech('T4', 's4', 0),  // nothing
    ];
    const totals = service.totals(techs, domain);
    expect(totals.total).toBe(4);
    expect(totals.enriched).toBe(3);
    expect(totals.mitigation).toBe(1);
    expect(totals.detection).toBe(1);
    expect(totals.control).toBe(1);
    const cov = service.coverage(techs, domain);
    expect(cov.covered).toBe(3);
    expect(cov.pct).toBe(75);
  });

  it('riskScore doubles for undefended threat-relevant techniques', () => {
    const undefended = tech('T3001', 's-3001', 0);
    const defended = tech('T3002', 's-3002', 1); // has mitigation
    domain.groupsByTechnique.set('s-3001', arr(2) as never);
    domain.groupsByTechnique.set('s-3002', arr(2) as never);
    // Both have threat pressure 4 (2 groups × 2); undefended is doubled.
    expect(service.riskScore(undefended, domain)).toBe(8);
    expect(service.riskScore(defended, domain)).toBe(4);
  });

  it('never throws when a service blows up — the signal is treated as absent', () => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: SigmaService, useValue: { getRuleCount: () => { throw new Error('not loaded'); } } },
        { provide: CARService, useValue: { getLiveCount: () => { throw new Error('boom'); } } },
        { provide: AtomicService, useValue: { getTestCount: () => { throw new Error('boom'); } } },
        { provide: D3fendService, useValue: { getCountermeasures: () => { throw new Error('boom'); } } },
        { provide: NistMappingService, useValue: { getControlCount: () => { throw new Error('boom'); } } },
        { provide: CriProfileService, useValue: { getControlCount: () => { throw new Error('boom'); } } },
        { provide: CisControlsService, useValue: { getControlCount: () => { throw new Error('boom'); } } },
        { provide: CsaCcmService, useValue: { getControlCount: () => { throw new Error('boom'); } } },
        { provide: M365ControlsService, useValue: { getControlCount: () => { throw new Error('boom'); } } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => { throw new Error('boom'); } } },
      ],
    });
    const s = TestBed.inject(EnrichmentService);
    expect(() => s.isEnriched(tech('T9', 's9', 0), emptyDomain())).not.toThrow();
    expect(s.isEnriched(tech('T9', 's9', 0), emptyDomain())).toBe(false);
    // The Known-tier entry points are guarded the same way.
    expect(() => s.referenceDefenseSignals(tech('T9', 's9', 0), emptyDomain())).not.toThrow();
    expect(s.isReferenceMapped(tech('T9', 's9', 0), emptyDomain())).toBe(false);
    expect(s.referenceDefenseTotals([tech('T9', 's9', 0)], emptyDomain()).mapped).toBe(0);
  });

  // ─── E1.7: Known-tier defensive reference signals (plan 4.1) ─────────────
  describe('referenceDefenseSignals (Known tier, E1.7)', () => {
    /**
     * A mixed fixture: each defensive input alone, one technique with all of
     * them, one with none, and one that is threat-side only.
     */
    function fixture(): Technique[] {
      counts.sigma.set('T1', 2);      // detection content (Sigma)
      counts.car.set('T2', 1);        // detection content (CAR)
      counts.nist.set('T3', 1);       // CTID control
      counts.d3fend.set('T4', 2);     // D3FEND
      counts.atomic.set('T5', 4);     // Atomic
      counts.sigma.set('T7', 1);
      counts.cis.set('T7', 1);
      counts.d3fend.set('T7', 1);
      counts.atomic.set('T7', 1);
      counts.cve.set('T9', 3);        // threat side only (CVE)
      domain.groupsByTechnique.set('s9', arr(4) as never); // threat side only (group)
      return [
        tech('T1', 's1'), tech('T2', 's2'), tech('T3', 's3'), tech('T4', 's4'),
        tech('T5', 's5'), tech('T6', 's6', 3) /* mitigation */, tech('T7', 's7', 1),
        tech('T8', 's8'), tech('T9', 's9'),
      ];
    }

    /** Every Known-tier number the service can produce for a set of techniques. */
    function knownSnapshot(techs: Technique[]) {
      return {
        totals: service.referenceDefenseTotals(techs, domain),
        perTechnique: techs.map(t => ({
          id: t.attackId,
          signals: service.referenceDefenseSignals(t, domain),
          mapped: service.isReferenceMapped(t, domain),
        })),
      };
    }

    it('carries only the five defensive reference inputs (no threat-intel or CVE field)', () => {
      const r = service.referenceDefenseSignals(tech('T1', 's1', 1), domain);
      expect(Object.keys(r).sort()).toEqual(['atomic', 'control', 'd3fend', 'detection', 'mitigation']);
    });

    it('marks a technique mapped when any one defensive reference input is present', () => {
      const cases: Array<[string, () => Technique]> = [
        ['mitigation (mitigationCount)', () => tech('M1', 'sm1', 1)],
        ['mitigation (domain relationship)', () => {
          domain.mitigationsByTechnique.set('sm2', arr(1) as never);
          return tech('M2', 'sm2', 0);
        }],
        ['Sigma', () => { counts.sigma.set('M3', 1); return tech('M3', 'sm3'); }],
        ['CAR', () => { counts.car.set('M4', 1); return tech('M4', 'sm4'); }],
        ['NIST', () => { counts.nist.set('M5', 1); return tech('M5', 'sm5'); }],
        ['CRI', () => { counts.cri.set('M6', 1); return tech('M6', 'sm6'); }],
        ['CIS', () => { counts.cis.set('M7', 1); return tech('M7', 'sm7'); }],
        ['CSA CCM', () => { counts.csa.set('M8', 1); return tech('M8', 'sm8'); }],
        ['M365', () => { counts.m365.set('M9', 1); return tech('M9', 'sm9'); }],
        ['D3FEND', () => { counts.d3fend.set('M10', 1); return tech('M10', 'sm10'); }],
        ['Atomic', () => { counts.atomic.set('M11', 1); return tech('M11', 'sm11'); }],
      ];
      for (const [label, make] of cases) {
        expect(service.isReferenceMapped(make(), domain)).withContext(label).toBe(true);
      }
      expect(service.isReferenceMapped(tech('M0', 'sm0'), domain)).withContext('nothing').toBe(false);
    });

    it('does not count a threat-only or CVE-only technique as mapped (isEnriched still does)', () => {
      const groupOnly = tech('T4001', 's-4001');
      domain.groupsByTechnique.set('s-4001', arr(5) as never);
      domain.softwareByTechnique.set('s-4001', arr(2) as never);
      domain.campaignsByTechnique.set('s-4001', arr(1) as never);
      counts.cve.set('T4002', 7);
      const cveOnly = tech('T4002', 's-4002');
      for (const t of [groupOnly, cveOnly]) {
        expect(service.isEnriched(t, domain)).withContext(`${t.attackId} threat side`).toBe(true);
        expect(service.isReferenceMapped(t, domain)).withContext(`${t.attackId} Known tier`).toBe(false);
      }
    });

    it('adding a group that uses a technique changes no Known-tier count', () => {
      const techs = fixture();
      const before = knownSnapshot(techs);
      const enrichedBefore = service.totals(techs, domain);
      expect(before.totals).toEqual({
        total: 9, mapped: 7, mitigation: 2, detection: 3, control: 2, d3fend: 2, atomic: 2,
      });

      // A new group (plus its software and a campaign) starts using EVERY technique.
      for (const t of techs) {
        const g = (domain.groupsByTechnique.get(t.id) as unknown as unknown[] | undefined) ?? [];
        domain.groupsByTechnique.set(t.id, [...g, 'new-group'] as never);
        domain.softwareByTechnique.set(t.id, ['new-software'] as never);
        domain.campaignsByTechnique.set(t.id, ['new-campaign'] as never);
      }

      expect(knownSnapshot(techs)).toEqual(before);
      // The Threat side did see the group: the old composite moves, the Known tier does not.
      const enrichedAfter = service.totals(techs, domain);
      expect(enrichedAfter.threatIntel).toBe(9);
      expect(enrichedAfter.threatIntel).toBeGreaterThan(enrichedBefore.threatIntel);
      expect(enrichedAfter.enriched).toBeGreaterThan(enrichedBefore.enriched);
    });

    it('adding CVE / KEV mappings to a technique changes no Known-tier count', () => {
      const techs = fixture();
      const before = knownSnapshot(techs);
      for (const t of techs) counts.cve.set(t.attackId, 10);
      expect(knownSnapshot(techs)).toEqual(before);
      expect(service.totals(techs, domain).cve).toBe(9);
    });

    it('never reads the threat-intel or CVE inputs at all', () => {
      const techs = fixture();
      const cveSpy = spyOn(TestBed.inject(AttackCveService), 'getCvesForTechnique').and.callThrough();
      const groupSpy = spyOn(domain.groupsByTechnique, 'get').and.callThrough();
      const softwareSpy = spyOn(domain.softwareByTechnique, 'get').and.callThrough();
      const campaignSpy = spyOn(domain.campaignsByTechnique, 'get').and.callThrough();
      knownSnapshot(techs);
      expect(cveSpy).not.toHaveBeenCalled();
      expect(groupSpy).not.toHaveBeenCalled();
      expect(softwareSpy).not.toHaveBeenCalled();
      expect(campaignSpy).not.toHaveBeenCalled();
      // Sanity: the Threat-side composite does read them.
      service.isEnriched(techs[8], domain);
      expect(cveSpy).toHaveBeenCalled();
      expect(groupSpy).toHaveBeenCalled();
    });

    it('agrees with signals() on the five shared families (signals() is built on it)', () => {
      const techs = fixture();
      for (const t of techs) {
        const all = service.signals(t, domain);
        const ref = service.referenceDefenseSignals(t, domain);
        expect({
          mitigation: all.mitigation, detection: all.detection, control: all.control,
          d3fend: all.d3fend, atomic: all.atomic,
        }).withContext(t.attackId).toEqual(ref);
      }
      const known = service.referenceDefenseTotals(techs, domain);
      const threatSide = service.totals(techs, domain);
      for (const k of ['mitigation', 'detection', 'control', 'd3fend', 'atomic'] as const) {
        expect(known[k]).withContext(k).toBe(threatSide[k]);
      }
    });

    it('returns all-false / zero totals for a missing technique or an empty set', () => {
      expect(service.referenceDefenseSignals(null as unknown as Technique, domain)).toEqual({
        mitigation: false, detection: false, control: false, d3fend: false, atomic: false,
      });
      expect(service.isReferenceMapped(undefined as unknown as Technique)).toBe(false);
      const zero = { total: 0, mapped: 0, mitigation: 0, detection: 0, control: 0, d3fend: 0, atomic: 0 };
      expect(service.referenceDefenseTotals([], domain)).toEqual(zero);
      expect(service.referenceDefenseTotals(undefined as unknown as Technique[], domain)).toEqual(zero);
    });
  });

  describe('mappedRollup (the one Known-tier count the summary surfaces read, E1.7)', () => {
    /** Two tactic columns over parents T1..T4, with one sub-technique under T1. */
    function rollupDomain(): Domain {
      counts.sigma.set('T1', 1);
      counts.atomic.set('T1.001', 1);
      counts.nist.set('T3', 2);
      counts.cve.set('T4', 5);                                   // threat side only
      const t1 = { ...tech('T1', 's1'), isSubtechnique: false } as Technique;
      const t1a = { ...tech('T1.001', 's1a'), isSubtechnique: true } as Technique;
      const t2 = { ...tech('T2', 's2', 2), isSubtechnique: false } as Technique;   // mitigation
      const t3 = { ...tech('T3', 's3'), isSubtechnique: false } as Technique;
      const t4 = { ...tech('T4', 's4'), isSubtechnique: false } as Technique;
      domain.groupsByTechnique.set('s4', arr(3) as never);      // threat side only
      return {
        ...domain,
        techniques: [t1, t1a, t2, t3, t4],
        tacticColumns: [
          { tactic: { id: 'x-ta-1', name: 'Execution', shortname: 'execution' }, techniques: [t1, t2] },
          { tactic: { id: 'x-ta-2', name: 'Discovery', shortname: 'discovery' }, techniques: [t3, t4] },
        ],
      } as unknown as Domain;
    }

    it('counts parent techniques by default and every technique with includeSubtechniques', () => {
      const d = rollupDomain();
      expect(service.mappedRollup(d).overall).toEqual({ total: 4, mapped: 3, pct: 75 });
      expect(service.mappedRollup(d, { includeSubtechniques: true }).overall).toEqual({ total: 5, mapped: 4, pct: 80 });
    });

    it('rolls each tactic column up with the same per-technique test as referenceDefenseTotals()', () => {
      const d = rollupDomain();
      const r = service.mappedRollup(d);
      expect(r.byTactic).toEqual([
        { tacticId: 'x-ta-1', tacticName: 'Execution', shortname: 'execution', total: 2, mapped: 2, pct: 100 },
        { tacticId: 'x-ta-2', tacticName: 'Discovery', shortname: 'discovery', total: 2, mapped: 1, pct: 50 },
      ]);
      for (const col of d.tacticColumns) {
        const row = r.byTactic.find(t => t.tacticId === col.tactic.id)!;
        expect(row.mapped).withContext(col.tactic.name).toBe(service.referenceDefenseTotals(col.techniques, d).mapped);
        expect(service.mappedCount(col.techniques, d)).withContext(col.tactic.name)
          .toEqual({ total: row.total, mapped: row.mapped, pct: row.pct });
      }
    });

    it('is threat-independent: a group, software, campaign or CVE on every technique changes no number', () => {
      const d = rollupDomain();
      const before = service.mappedRollup(d);
      expect(service.totals(d.techniques, d).threatIntel).toBe(1);
      for (const t of d.techniques) {
        d.groupsByTechnique.set(t.id, arr(2) as never);
        d.softwareByTechnique.set(t.id, arr(1) as never);
        d.campaignsByTechnique.set(t.id, arr(1) as never);
        counts.cve.set(t.attackId, 1);
      }
      expect(service.mappedRollup(d)).toEqual(before);
      // Control: the threat links really were added (1 technique before, all 5 after).
      expect(service.totals(d.techniques, d).threatIntel).toBe(5);
    });

    it('returns an empty rollup for a missing domain, and mappedPct rounds one way everywhere', () => {
      expect(service.mappedRollup(null)).toEqual({ overall: { total: 0, mapped: 0, pct: 0 }, byTactic: [] });
      expect(service.mappedRollup(undefined)).toEqual({ overall: { total: 0, mapped: 0, pct: 0 }, byTactic: [] });
      expect(mappedPct(0, 0)).toBe(0);
      expect(mappedPct(1, 3)).toBe(33);
      expect(mappedPct(2, 3)).toBe(67);
      expect(mappedPct(1, 8)).toBe(13);
    });

    it('ranks breadth over the five reference inputs only (referenceSignalCount)', () => {
      const d = rollupDomain();
      const [t1, , t2, t3, t4] = d.techniques;
      counts.d3fend.set('T1', 1);
      expect(service.referenceSignalCount(t1, d)).toBe(2);      // detection + D3FEND
      expect(service.referenceSignalCount(t2, d)).toBe(1);      // mitigation
      expect(service.referenceSignalCount(t3, d)).toBe(1);      // control
      expect(service.referenceSignalCount(t4, d)).toBe(0);      // CVE + group: threat side only
      expect(service.signalCount(t4, d)).toBe(2);               // ...which the Threat-side count does see
    });
  });
});
