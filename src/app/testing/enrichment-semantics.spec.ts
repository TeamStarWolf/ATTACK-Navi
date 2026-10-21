// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization of the signal families EnrichmentService.signals() reports
// and of the two yes/no tests over them (models/known-signals.ts), checked over
// every technique of the fixed fixture domain against an independent oracle
// written from the stub data. P2-08 deleted EnrichmentService.isEnriched (any
// family, threat-intel and CVE links included: now hasAnySignal) and
// hasDefensiveSignal (now hasDefensiveReference); this spec pins that the
// Known 'mapped' count, which every summary surface and coverage-breakdown's
// headline show, ignores the threat inputs that hasAnySignal counts.
//
// These specs pin CURRENT semantics, including the ones the audit questions
// ("reference availability is not deployed defense"). If the definition is
// deliberately changed, these expectations are meant to change with it.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { hasAnySignal, hasDefensiveReference } from '../models/known-signals';
import { EnrichmentService } from '../services/enrichment.service';
import { ImplementationService } from '../services/implementation.service';
import { CoverageBreakdownComponent } from '../components/coverage-breakdown/coverage-breakdown.component';
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

/** Known 'mapped' straight from the oracle: any of the five defensive reference inputs. */
function oracleMapped(t: Technique, d: Domain): boolean {
  const f = families(t, d);
  return f.mitigation || f.detection || f.atomic || f.d3fend || f.control;
}

describe('EnrichmentService.signals semantics and the known-signals tests (fixture domain)', () => {
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

  it('hasAnySignal is true exactly when ANY of the seven signal families is present', () => {
    for (const t of domain.techniques) {
      const f = families(t, domain);
      const any = Object.values(f).some(Boolean);
      expect(hasAnySignal(enrichment.signals(t, domain))).withContext(t.attackId).toBe(any);
      expect(enrichment.signals(t, domain)).withContext(t.attackId).toEqual(f);
    }
  });

  it('hasAnySignal counts threat-intel links alone: every technique used by a group has a signal', () => {
    const used = domain.techniques.filter(t => (domain.groupsByTechnique.get(t.id)?.length ?? 0) > 0);
    expect(used.length).toBeGreaterThan(0);
    for (const t of used) expect(hasAnySignal(enrichment.signals(t, domain))).withContext(t.attackId).toBeTrue();
  });

  it('[P2-08] the Known mapped count ignores threat inputs: a group using every technique and CVEs on every technique move hasAnySignal, never mapped', () => {
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    const mappedBefore = enrichment.mappedRollup(domain);
    expect(mappedBefore.overall.mapped).toBe(parents.filter(t => oracleMapped(t, domain)).length);
    // Strip every threat link first, so the threat side has room to rise.
    for (const t of domain.techniques) {
      domain.groupsByTechnique.delete(t.id);
      domain.softwareByTechnique.delete(t.id);
      domain.campaignsByTechnique.delete(t.id);
    }
    const stripped = enrichment.mappedRollup(domain);
    const anyStripped = parents.filter(t => hasAnySignal(enrichment.signals(t, domain))).length;
    expect(stripped).withContext('removing every threat link moves no Known number').toEqual(mappedBefore);
    // A new group (with software and a campaign) starts using EVERY technique.
    for (const t of domain.techniques) {
      domain.groupsByTechnique.set(t.id, ['new-group'] as never);
      domain.softwareByTechnique.set(t.id, ['new-software'] as never);
      domain.campaignsByTechnique.set(t.id, ['new-campaign'] as never);
    }
    const anyAfter = parents.filter(t => hasAnySignal(enrichment.signals(t, domain))).length;
    expect(anyAfter).withContext('the threat side sees the group').toBe(parents.length);
    expect(anyAfter).toBeGreaterThan(anyStripped);
    expect(enrichment.mappedRollup(domain)).withContext('the Known count does not').toEqual(mappedBefore);
    for (const t of domain.techniques) {
      expect(enrichment.isReferenceMapped(t, domain)).withContext(t.attackId).toBe(oracleMapped(t, domain));
    }
  });

  it('ignores implementation status: marking every mitigation "not-started" changes nothing', () => {
    const before = domain.techniques.map(t => hasAnySignal(enrichment.signals(t, domain)));
    const impl = TestBed.inject(ImplementationService);
    for (const m of domain.mitigations) impl.setStatus(m.id, 'not-started');
    const after = domain.techniques.map(t => hasAnySignal(enrichment.signals(t, domain)));
    expect(after).toEqual(before);
    // ...and a mitigated technique keeps a defensive reference although nothing is deployed.
    const mitigated = domain.techniques.find(t => t.mitigationCount > 0)!;
    expect(hasDefensiveReference(enrichment.signals(mitigated, domain))).toBeTrue();
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

  it('totals() agrees with hasAnySignal / hasDefensiveReference per technique', () => {
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    const totals = enrichment.totals(parents, domain);
    expect(totals.total).toBe(parents.length);
    expect(totals.enriched).toBe(parents.filter(t => hasAnySignal(enrichment.signals(t, domain))).length);
    expect(totals.defended).toBe(parents.filter(t => hasDefensiveReference(enrichment.signals(t, domain))).length);
    expect(totals.defended).toBeLessThanOrEqual(totals.enriched);
    expect(enrichment.coverage(parents, domain)).toEqual({
      covered: totals.enriched,
      total: parents.length,
      pct: Math.round((totals.enriched / parents.length) * 100),
    });
  });

  // ── coverage-breakdown (Status workspace): 'Enriched' became Known 'mapped' (P2-08) ──
  describe('coverage-breakdown headline', () => {
    function render(): HTMLElement {
      const f = TestBed.createComponent(CoverageBreakdownComponent);
      f.componentRef.setInput('domain', domain);
      f.detectChanges();
      return f.nativeElement as HTMLElement;
    }
    const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
    const num = (el: HTMLElement, key: string) => Number(text(el.querySelector(`[data-posture="${key}"]`)));

    it("shows Known 'mapped' (the rollup's Known number), not the old Enriched count, and keeps the per-family rows", () => {
      const parents = domain.techniques.filter(t => !t.isSubtechnique);
      const known = enrichment.mappedRollup(domain).overall;
      const el = render();
      expect(text(el.querySelector('.cov-head-label'))).toBe('Known: mapped');
      expect([num(el, 'known-mapped'), num(el, 'known-total')]).toEqual([known.mapped, known.total]);
      expect(text(el.querySelector('[data-testid="cov-known-pct"]'))).toBe(`${known.pct}%`);
      expect(known.mapped).toBe(parents.filter(t => oracleMapped(t, domain)).length);
      // The fixture has threat-only parents, so the old Enriched headline would differ.
      const enriched = enrichment.totals(parents, domain).enriched;
      expect(enriched).toBeGreaterThan(known.mapped);
      expect(el.textContent).not.toMatch(/\benriched\b/i);
      // The second headline and the seven per-family rows stay.
      expect(text(el.querySelectorAll('.cov-head-label')[1])).toBe('Has mapped countermeasure');
      expect(Array.from(el.querySelectorAll('.cov-row-label')).map(r => text(r))).toEqual([
        'ATT&CK Mitigations', 'Detections', 'D3FEND', 'Control Frameworks', 'Atomic Red Team', 'Threat Intel', 'CVE / KEV',
      ]);
    });

    it('the headline does not move when a group starts using every technique', () => {
      const before = num(render(), 'known-mapped');
      for (const t of domain.techniques) domain.groupsByTechnique.set(t.id, ['new-group'] as never);
      const el = render();
      expect(num(el, 'known-mapped')).toBe(before);
      // The Threat Intel row does see the group.
      const threatRow = Array.from(el.querySelectorAll('.cov-row')).find(r => text(r.querySelector('.cov-row-label')) === 'Threat Intel')!;
      expect(text(threatRow.querySelector('.cov-row-val strong'))).toBe(String(domain.techniques.filter(t => !t.isSubtechnique).length));
    });
  });
});
