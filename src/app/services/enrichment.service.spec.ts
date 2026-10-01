// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { EnrichmentService } from './enrichment.service';
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
  });
});
