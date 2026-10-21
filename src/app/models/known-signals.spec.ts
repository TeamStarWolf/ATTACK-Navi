// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// known-signals (Phase 2 design §3 P2-08): hasDefensiveReference and
// hasAnySignal give the SAME answers as the deleted
// EnrichmentService.hasDefensiveSignal and isEnriched, on every technique of
// the lens fixture (parents and sub-techniques) and on every combination of
// the seven families. The old answers are computed from the deleted methods'
// bodies, inlined below verbatim, not by calling them (they no longer exist).
// riskScore, the third caller, is checked the same way; the matrix dim set and
// the dashboard counters are pinned byte for byte in legacy-risk-dim.spec.ts.
//
// The unit cases moved here from enrichment.service.spec.ts.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import type { Domain } from './domain';
import type { Technique } from './technique';
import { type SignalFamilies, hasAnySignal, hasDefensiveReference } from './known-signals';
import { EnrichmentService } from '../services/enrichment.service';
import { kevScores, parseFixtureDomain, resetBrowserState, signalStubProviders } from '../testing/lens-harness';

// ── The deleted logic, inlined verbatim (enrichment.service.ts before P2-08) ──
/** The body of the deleted EnrichmentService.isEnriched. */
function deletedIsEnriched(svc: EnrichmentService, tech: Technique, domain?: Domain | null): boolean {
  const s = svc.signals(tech, domain);
  return (
    s.mitigation || s.detection || s.atomic ||
    s.d3fend || s.control || s.threatIntel || s.cve
  );
}

/** The body of the deleted EnrichmentService.hasDefensiveSignal. */
function deletedHasDefensiveSignal(svc: EnrichmentService, tech: Technique, domain?: Domain | null): boolean {
  const s = svc.signals(tech, domain);
  return s.mitigation || s.detection || s.control || s.d3fend;
}

/** The body of riskScore before P2-08, over the deleted hasDefensiveSignal. */
function deletedRiskScore(svc: EnrichmentService, tech: Technique, domain?: Domain | null, kevScore = 0): number {
  const len = (v: unknown[] | undefined) => v?.length ?? 0;
  const groups = len(domain?.groupsByTechnique?.get(tech.id));
  const software = len(domain?.softwareByTechnique?.get(tech.id));
  const campaigns = len(domain?.campaignsByTechnique?.get(tech.id));
  const threat = groups * 2 + software + campaigns;
  const exposure = threat + (kevScore > 0 ? kevScore * 3 : 0);
  return exposure * (deletedHasDefensiveSignal(svc, tech, domain) ? 1 : 2);
}

const FAMILIES = ['mitigation', 'detection', 'atomic', 'd3fend', 'control', 'threatIntel', 'cve'] as const;
const none: SignalFamilies = { mitigation: false, detection: false, atomic: false, d3fend: false, control: false, threatIntel: false, cve: false };
const only = (...on: (typeof FAMILIES)[number][]): SignalFamilies => ({ ...none, ...Object.fromEntries(on.map(k => [k, true])) });

describe('known-signals: the pure tests that replaced isEnriched and hasDefensiveSignal (P2-08)', () => {
  // ── Unit cases (moved from enrichment.service.spec.ts) ─────────────────────
  it('a technique with zero of every signal has no signal and no defensive reference', () => {
    expect(hasAnySignal(none)).toBeFalse();
    expect(hasDefensiveReference(none)).toBeFalse();
  });

  it('a mitigation-only, detection-only, control-only or D3FEND-only technique has both', () => {
    for (const k of ['mitigation', 'detection', 'control', 'd3fend'] as const) {
      expect(hasAnySignal(only(k))).withContext(k).toBeTrue();
      expect(hasDefensiveReference(only(k))).withContext(k).toBeTrue();
    }
  });

  it('hasDefensiveReference excludes atomic / threat-intel / cve; hasAnySignal counts them', () => {
    for (const k of ['atomic', 'threatIntel', 'cve'] as const) {
      expect(hasAnySignal(only(k))).withContext(k).toBeTrue();
      expect(hasDefensiveReference(only(k))).withContext(k).toBeFalse();
    }
    const enrichedNotDefended = only('atomic', 'cve', 'threatIntel');
    expect(hasAnySignal(enrichedNotDefended)).toBeTrue();
    expect(hasDefensiveReference(enrichedNotDefended)).toBeFalse();
    // Add a real control: now a defensive reference.
    expect(hasDefensiveReference({ ...enrichedNotDefended, control: true })).toBeTrue();
  });

  it('every one of the 128 family combinations gives the deleted expressions', () => {
    for (let mask = 0; mask < 1 << FAMILIES.length; mask++) {
      const s = only(...FAMILIES.filter((_, i) => mask & (1 << i)));
      const label = JSON.stringify(s);
      expect(hasAnySignal(s)).withContext(label).toBe(s.mitigation || s.detection || s.atomic || s.d3fend || s.control || s.threatIntel || s.cve);
      expect(hasDefensiveReference(s)).withContext(label).toBe(s.mitigation || s.detection || s.control || s.d3fend);
    }
  });

  // ── Every fixture technique, through the real EnrichmentService ─────────────
  describe('on every lens-fixture technique (identical results)', () => {
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

    /** Compare both functions with the deleted methods on every technique; returns how often each was true. */
    function compare(d: Domain | null, label: string): { any: number; defensive: number } {
      let any = 0;
      let defensive = 0;
      for (const t of domain.techniques) {
        const s = enrichment.signals(t, d);
        const a = hasAnySignal(s);
        const r = hasDefensiveReference(s);
        expect(a).withContext(`${label} ${t.attackId} hasAnySignal = isEnriched`).toBe(deletedIsEnriched(enrichment, t, d));
        expect(r).withContext(`${label} ${t.attackId} hasDefensiveReference = hasDefensiveSignal`).toBe(deletedHasDefensiveSignal(enrichment, t, d));
        if (a) any++;
        if (r) defensive++;
      }
      return { any, defensive };
    }

    it('with the domain loaded, parents and sub-techniques', () => {
      expect(domain.techniques.some(t => t.isSubtechnique)).toBeTrue();
      const n = compare(domain, 'loaded');
      // Non-degenerate: the fixture has techniques with and without a defensive reference.
      expect(n.defensive).toBeGreaterThan(0);
      expect(n.defensive).toBeLessThan(domain.techniques.length);
      expect(n.any).toBeGreaterThan(n.defensive);
    });

    it('with no domain (threat intel absent)', () => {
      const n = compare(null, 'no domain');
      expect(n.any).toBeLessThan(domain.techniques.length);
    });

    it('with every threat link removed, so hasAnySignal is false somewhere', () => {
      for (const t of domain.techniques) {
        domain.groupsByTechnique.delete(t.id);
        domain.softwareByTechnique.delete(t.id);
        domain.campaignsByTechnique.delete(t.id);
      }
      const n = compare(domain, 'threat stripped');
      expect(n.any).toBeGreaterThan(0);
      expect(n.any).toBeLessThan(domain.techniques.length);
    });

    it('riskScore (the third caller) equals the deleted formula on every technique, with and without KEV scores', () => {
      const kev = kevScores();
      expect(kev.size).toBeGreaterThan(0);
      let doubled = 0;
      for (const t of domain.techniques) {
        for (const k of [0, kev.get(t.attackId) ?? 0, 3]) {
          expect(enrichment.riskScore(t, domain, k)).withContext(`${t.attackId} kev ${k}`).toBe(deletedRiskScore(enrichment, t, domain, k));
        }
        if (!deletedHasDefensiveSignal(enrichment, t, domain) && enrichment.riskScore(t, domain) > 0) doubled++;
      }
      expect(doubled).withContext('some techniques take the undefended doubling').toBeGreaterThan(0);
    });
  });
});
