// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization of what EnrichmentService.isEnriched — the app's single
// definition of "coverage" — means today, checked over every technique of the
// fixed fixture domain against an independent oracle written from the stub data.
//
// These specs pin CURRENT semantics, including the ones the audit questions
// ("reference availability is not deployed defense"). If the definition is
// deliberately changed, these expectations are meant to change with it.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { EnrichmentService } from '../services/enrichment.service';
import { ImplementationService } from '../services/implementation.service';
import { cvesFor, parseFixtureDomain, resetBrowserState, signal, signalStubProviders } from './lens-harness';

/** Oracle: the seven signal families, computed straight from the fixture + stubs. */
function families(t: Technique, d: Domain) {
  const id = t.attackId;
  const threat =
    (d.groupsByTechnique.get(t.id)?.length ?? 0) +
    (d.softwareByTechnique.get(t.id)?.length ?? 0) +
    (d.campaignsByTechnique.get(t.id)?.length ?? 0);
  const control = signal('nist', id) + signal('cri', id) + signal('cis', id) + signal('csa', id) + signal('m365-ctl', id);
  return {
    mitigation: t.mitigationCount > 0,
    detection: signal('sigma', id) + signal('car-live', id) > 0,
    atomic: signal('atomic', id) > 0,
    d3fend: signal('d3fend', id) > 0,
    control: control > 0,
    threatIntel: threat > 0,
    cve: cvesFor(id).length > 0,
  };
}

describe('EnrichmentService.isEnriched semantics (fixture domain)', () => {
  let domain: Domain;
  let enrichment: EnrichmentService;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders()],
    });
    enrichment = TestBed.inject(EnrichmentService);
  });

  afterEach(() => resetBrowserState());

  it('is true exactly when ANY of the seven signal families is present', () => {
    for (const t of domain.techniques) {
      const f = families(t, domain);
      const any = Object.values(f).some(Boolean);
      expect(enrichment.isEnriched(t, domain)).withContext(t.attackId).toBe(any);
      expect(enrichment.signals(t, domain)).withContext(t.attackId).toEqual(f);
    }
  });

  it('counts threat-intel links alone as coverage: every technique used by a group is "enriched"', () => {
    const used = domain.techniques.filter(t => (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0);
    expect(used.length).toBeGreaterThan(0);
    for (const t of used) expect(enrichment.isEnriched(t, domain)).withContext(t.attackId).toBeTrue();
  });

  it('ignores implementation status: marking every mitigation "not-started" changes nothing', () => {
    const before = domain.techniques.map(t => enrichment.isEnriched(t, domain));
    const impl = TestBed.inject(ImplementationService);
    for (const m of domain.mitigations) impl.setStatus(m.id, 'not-started');
    const after = domain.techniques.map(t => enrichment.isEnriched(t, domain));
    expect(after).toEqual(before);
    // ...and a mitigated technique stays "defended" although nothing is deployed.
    const mitigated = domain.techniques.find(t => t.mitigationCount > 0)!;
    expect(enrichment.hasDefensiveSignal(mitigated, domain)).toBeTrue();
  });

  it('does not roll a sub-technique up into its parent (each id is judged on its own)', () => {
    const parent = domain.techniques.find(t => t.attackId === 'T1003')!;
    const sub = parent.subtechniques[0];
    expect(enrichment.signals(sub, domain)).toEqual(families(sub, domain));
    expect(enrichment.signals(sub, domain).mitigation).toBe(sub.mitigationCount > 0);
  });

  it('without a domain, threat intel is absent but mitigation still comes from the technique', () => {
    const t = domain.techniques.find(x => x.mitigationCount > 0 && (domain.groupsByTechnique.get(x.id)?.length ?? 0) > 0)!;
    const s = enrichment.signals(t, null);
    expect(s.threatIntel).toBeFalse();
    expect(s.mitigation).toBeTrue();
  });

  it('totals() agrees with isEnriched / hasDefensiveSignal per technique', () => {
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    const totals = enrichment.totals(parents, domain);
    expect(totals.total).toBe(parents.length);
    expect(totals.enriched).toBe(parents.filter(t => enrichment.isEnriched(t, domain)).length);
    expect(totals.defended).toBe(parents.filter(t => enrichment.hasDefensiveSignal(t, domain)).length);
    expect(totals.defended).toBeLessThanOrEqual(totals.enriched);
    expect(enrichment.coverage(parents, domain)).toEqual({
      covered: totals.enriched,
      total: parents.length,
      pct: Math.round((totals.enriched / parents.length) * 100),
    });
  });
});
