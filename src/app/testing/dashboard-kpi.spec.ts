// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization of the dashboard KPIs on the fixed fixture domain. Every
// expected number is recomputed here by an independent oracle from the fixture
// and the stub signal data (lens-harness.ts), then checked twice: on the
// component's `stats` and on the rendered Mapped Summary widget.
//
// The last describe pins the threat-gap counters before and after P2-09
// (E2.1-d3; R9): criticalRiskCount and kevExposedGapCount on a fresh profile,
// on P2-07's exact seed ('seeded') and on the unrecorded-gap variant
// ('gapSeeded', posture-seed.ts). Before = the legacy predicate (used by a
// group / KEV-mapped, and no defensive reference); after = the component, which
// also leaves out covered, proven and stale techniques.
//
// kevExposedGapCount is 0 before and after on every profile: no fixture
// technique is both KEV-mapped and undefended. That pin alone cannot see a
// revert of the KEV rule to hasDefensiveReference alone, so the KEV case below
// gives a dark parent a KEV CVE and then covers it; only the posture-aware rule
// takes it back out.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { DashboardPanelComponent } from '../components/dashboard-panel/dashboard-panel.component';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { AttackCveService } from '../services/attack-cve.service';
import { DataService } from '../services/data.service';
import { ImplementationService } from '../services/implementation.service';
import { PostureService } from '../services/posture.service';
import { TechniqueMarksService } from '../services/technique-marks.service';
import { refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { type PostureSeedPicks, postureSeedToday, seedPostureProfile } from './posture-seed';
import {
  DARK_TECHNIQUES, IMPL_CYCLE, controlsProvider, cvesFor, parseFixtureDomain, resetBrowserState, signal,
  signalStubProviders, sortedMitigations,
} from './lens-harness';

/** Oracle for one technique, straight from the stubs (same families EnrichmentService uses). */
function oracle(t: Technique, d: Domain) {
  const id = t.attackId;
  const groups = d.groupsByTechnique.get(t.id)?.length ?? 0;
  const threat = groups + (d.softwareByTechnique.get(t.id)?.length ?? 0) + (d.campaignsByTechnique.get(t.id)?.length ?? 0);
  const mitigation = t.mitigationCount > 0;
  const detection = signal('sigma', id) + signal('car-live', id) > 0;
  const control = signal('nist', id) + signal('cri', id) + signal('cis', id) + signal('csa', id) + signal('m365-ctl', id) > 0;
  const d3fend = signal('d3fend', id) > 0;
  const atomic = signal('atomic', id) > 0;
  const cve = cvesFor(id).length > 0;
  const kev = Math.min(cvesFor(id).length, signal('kev', id)) > 0;
  const defended = mitigation || detection || control || d3fend;
  return {
    groups, mitigation, detection, control, d3fend, atomic, cve, kev, defended,
    mapped: defended || atomic,
    enriched: defended || atomic || threat > 0 || cve,
    car: signal('car', id) > 0,
  };
}

describe('Dashboard KPIs (fixture domain)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<DashboardPanelComponent>;
  let parents: Technique[];

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    parents = domain.techniques.filter(t => !t.isSubtechnique);
    TestBed.configureTestingModule({
      imports: [DashboardPanelComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        controlsProvider(domain),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    const impl = TestBed.inject(ImplementationService);
    sortedMitigations(domain).forEach((m, i) => impl.setStatus(m.id, IMPL_CYCLE[i % IMPL_CYCLE.length]));
    fixture = TestBed.createComponent(DashboardPanelComponent);
    fixture.detectChanges();
  });

  afterEach(() => resetBrowserState());

  const pct = (n: number) => Math.round((n / parents.length) * 100);
  const count = (pred: (o: ReturnType<typeof oracle>) => boolean) => parents.filter(t => pred(oracle(t, domain))).length;

  function rendered(label: string): string {
    const stat = [...(fixture.nativeElement as HTMLElement).querySelectorAll('.widget-coverage-summary .mini-stat')]
      .find(el => el.querySelector('.mini-stat-label')?.textContent?.trim() === label);
    return stat?.querySelector('.mini-stat-value')?.textContent?.trim() ?? '(not rendered)';
  }

  it('counts parent techniques only, and mapped = any of the five defensive reference inputs (no threat or CVE links)', () => {
    const stats = fixture.componentInstance.stats!;
    expect(stats.totalTechniques).toBe(45);
    expect(stats.coveredTechniques).toBe(count(o => o.mapped));
    // The fixture has threat-only techniques, so the old enriched count would differ.
    expect(count(o => o.enriched)).toBeGreaterThan(stats.coveredTechniques);
    expect(stats.uncoveredCount).toBe(45 - stats.coveredTechniques);
    expect(stats.coveragePct).toBe(pct(stats.coveredTechniques));
    expect(stats.mitigationCoveragePct).toBe(pct(count(o => o.mitigation)));
    expect(stats.controlCoveragePct).toBe(pct(count(o => o.control)));
  });

  it('detection content mapped is Sigma rules or CAR analytics; the per-source counts stay alongside', () => {
    const stats = fixture.componentInstance.stats!;
    expect(stats.withCarCount).toBe(count(o => o.car));
    expect(stats.withAtomicCount).toBe(count(o => o.atomic));
    expect(stats.withD3fendCount).toBe(count(o => o.d3fend));
    expect(stats.detectionCoveragePct).toBe(pct(count(o => o.detection)));
  });

  it('critical risk = used by a group AND no mitigation / detection / control / D3FEND', () => {
    const stats = fixture.componentInstance.stats!;
    const critical = parents.filter(t => { const o = oracle(t, domain); return o.groups > 0 && !o.defended; });
    // The fixture's unmitigated parents get no stub signal at all (DARK_TECHNIQUES).
    expect(critical.map(t => t.attackId).sort()).toEqual(['T1007', 'T1082', 'T1113', 'T1526', 'T1531']);
    expect(stats.criticalRiskCount).toBe(critical.length);
    const byGroups = [...critical].sort((a, b) => oracle(b, domain).groups - oracle(a, domain).groups).slice(0, 10);
    expect(stats.topRiskTechniques.map(r => r.attackId)).toEqual(byGroups.map(t => t.attackId));
    expect(stats.cveExposedCount).toBe(count(o => o.cve));
  });

  it('the hidden legacy postureScore is deleted (P2-08); the KEV-gap counter it read stays', () => {
    const stats = fixture.componentInstance.stats!;
    expect('postureScore' in stats).toBeFalse();
    expect(stats.kevExposedGapCount).toBe(count(o => o.kev && !o.defended));
  });

  it('implementation KPIs summarise the stored mitigation statuses', () => {
    const stats = fixture.componentInstance.stats!;
    const statuses = sortedMitigations(domain).map((_, i) => IMPL_CYCLE[i % IMPL_CYCLE.length]);
    expect(stats.totalMitigations).toBe(domain.mitigations.length);
    expect(stats.implementedCount).toBe(statuses.filter(s => s === 'implemented').length);
    expect(stats.inProgressCount).toBe(statuses.filter(s => s === 'in-progress').length);
    expect(stats.plannedCount).toBe(statuses.filter(s => s === 'planned').length);
    expect(stats.notStartedCount).toBe(statuses.filter(s => s === 'not-started').length);
  });

  it('renders the headline KPIs in the Mapped Summary widget, labelled with the Known-rung word', () => {
    const stats = fixture.componentInstance.stats!;
    expect(rendered('Total Techniques')).toBe('45');
    expect(rendered('Techniques mapped')).toBe(String(stats.coveredTechniques));
    expect(rendered('Mapped')).toBe(`${stats.coveragePct}%`);
    expect(rendered('Mitigation mapped')).toBe(`${stats.mitigationCoveragePct}%`);
    expect(rendered('Detection content mapped')).toBe(`${stats.detectionCoveragePct}%`);
    expect(rendered('Control mapped')).toBe(`${stats.controlCoveragePct}%`);
    for (const old of ['Enriched', 'Coverage', 'Mitigation coverage', 'Detection coverage', 'Control coverage']) {
      expect(rendered(old)).withContext(old).toBe('(not rendered)');
    }
    // E1.5 hid the threat-weighted composite (postureScore) and P2-08 deleted it:
    // it moved with group usage, so it was not Known-rung data. No label for it renders.
    expect(rendered('Reference depth index')).toBe('(not rendered)');
    expect(rendered('Posture score')).toBe('(not rendered)');
  });
});

/**
 * Pinned before and after values on the fixture (P2-09). Before is P2-01's
 * legacy-baseline riskDim.<fresh|seeded>.dashboard (gapSeeded's before is
 * seeded's: the legacy rule reads no owner data); after is riskDimAfter.
 * The kevExposedGapCount pins (0 -> 0) do not discriminate on their own; the
 * KEV case in each profile does.
 */
const THREAT_GAP_PINS = {
  fresh: { before: { criticalRiskCount: 5, kevExposedGapCount: 0 }, after: { criticalRiskCount: 5, kevExposedGapCount: 0 } },
  seeded: { before: { criticalRiskCount: 5, kevExposedGapCount: 0 }, after: { criticalRiskCount: 5, kevExposedGapCount: 0 } },
  gapSeeded: { before: { criticalRiskCount: 5, kevExposedGapCount: 0 }, after: { criticalRiskCount: 3, kevExposedGapCount: 0 } },
} as const;

for (const profile of ['fresh', 'seeded', 'gapSeeded'] as const) {
  describe(`Dashboard threat-gap counters before and after posture, ${profile} profile (P2-09, E2.1-d3)`, () => {
    let domain: Domain;
    let parents: Technique[];
    let picks: PostureSeedPicks | null;
    let fixture: ComponentFixture<DashboardPanelComponent>;

    beforeEach(() => {
      resetBrowserState();
      domain = parseFixtureDomain();
      parents = domain.techniques.filter(t => !t.isSubtechnique);
      TestBed.configureTestingModule({
        imports: [DashboardPanelComponent],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), ...signalStubProviders(), postureSeedToday()],
      });
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      picks = profile === 'fresh' ? null : seedPostureProfile(domain, profile);
      fixture = TestBed.createComponent(DashboardPanelComponent);
      fixture.detectChanges();
    });

    afterEach(() => resetBrowserState());

    it('before: the legacy predicate gives the P2-01 values', () => {
      const legacy = {
        criticalRiskCount: parents.filter(t => { const o = oracle(t, domain); return o.groups > 0 && !o.defended; }).length,
        kevExposedGapCount: parents.filter(t => { const o = oracle(t, domain); return o.kev && !o.defended; }).length,
      };
      expect(legacy).toEqual(THREAT_GAP_PINS[profile].before);
    });

    it('after: the component leaves out covered, proven and stale techniques; the scope line reads "used by any ATT&CK group"', () => {
      const stats = fixture.componentInstance.stats!;
      const pinned = THREAT_GAP_PINS[profile].after;
      expect({ criticalRiskCount: stats.criticalRiskCount, kevExposedGapCount: stats.kevExposedGapCount }).toEqual(pinned);

      // Oracle: the legacy predicate minus the techniques with Covered-or-above owner data.
      const posture = TestBed.inject(PostureService);
      const recorded = (t: Technique) => ['covered', 'proven', 'stale'].includes(posture.stateFor(t).bucket);
      const critical = parents.filter(t => { const o = oracle(t, domain); return o.groups > 0 && !o.defended && !recorded(t); });
      expect(critical.length).toBe(pinned.criticalRiskCount);
      expect(stats.topRiskTechniques.map(r => r.attackId).sort()).toEqual(critical.map(t => t.attackId).sort());
      if (profile === 'gapSeeded') {
        expect(stats.topRiskTechniques.map(r => r.attackId)).not.toContain(picks!.confirmed.attackId);
        expect(stats.topRiskTechniques.map(r => r.attackId)).not.toContain(picks!.proof.attackId);
      } else {
        // Fresh, and P2-07's seed (its recorded picks are mitigated parents): unchanged.
        expect(pinned).withContext(`${profile}: unchanged`).toEqual(THREAT_GAP_PINS[profile].before);
      }

      const scope = (fixture.nativeElement as HTMLElement).querySelector('[data-critical-risk-scope]');
      expect(scope?.textContent?.trim()).toBe(`${pinned.criticalRiskCount} critical-risk techniques, used by any ATT&CK group`);
    });

    it('KEV gap: a dark parent given a KEV CVE counts until the owner covers it (a revert to the Known test alone keeps it)', () => {
      const stats = () => {
        const f = TestBed.createComponent(DashboardPanelComponent);
        f.detectChanges();
        const v = f.componentInstance.stats!;
        f.destroy();
        return { criticalRiskCount: v.criticalRiskCount, kevExposedGapCount: v.kevExposedGapCount };
      };
      const posture = TestBed.inject(PostureService);
      const taken = new Set(picks ? [picks.confirmed, picks.proof, picks.failed, picks.notReproducible] : []);
      const probe = parents.slice().sort((a, b) => a.attackId.localeCompare(b.attackId))
        .find(t => DARK_TECHNIQUES.has(t.attackId) && !taken.has(t) && oracle(t, domain).groups > 0)!;
      expect(probe).withContext('an untouched dark parent used by a group').toBeDefined();
      expect(oracle(probe, domain).defended).toBeFalse();
      expect(posture.stateFor(probe).bucket).toBe('none');

      const cves = TestBed.inject(AttackCveService) as unknown as { getKevCvesForTechnique(id: string): unknown[] };
      const original = cves.getKevCvesForTechnique.bind(cves);
      cves.getKevCvesForTechnique = (id: string) => (id === probe.attackId ? [{ cveId: 'CVE-2024-0001' }] : original(id));
      const start = THREAT_GAP_PINS[profile].after;
      expect(stats()).toEqual({ criticalRiskCount: start.criticalRiskCount, kevExposedGapCount: start.kevExposedGapCount + 1 });

      // Covered (a technique confirmation): out of both counters. Under the
      // legacy rule (no defensive reference alone) it would still count.
      const key = techniqueRefKey(refForTechnique(probe, 'enterprise', domain.attackVersion));
      expect(TestBed.inject(TechniqueMarksService).confirm(key)).toBeTrue();
      expect(posture.stateFor(probe).bucket).toBe('covered');
      expect(oracle(probe, domain).defended).withContext('still no defensive reference').toBeFalse();
      expect(stats()).toEqual({ criticalRiskCount: start.criticalRiskCount - 1, kevExposedGapCount: start.kevExposedGapCount });

      if (profile === 'gapSeeded') {
        // The covered and the proven pick, given a KEV CVE, are not KEV gaps either.
        const kevd = new Set([probe.attackId, picks!.confirmed.attackId, picks!.proof.attackId]);
        cves.getKevCvesForTechnique = (id: string) => (kevd.has(id) ? [{ cveId: 'CVE-2024-0001' }] : original(id));
        expect(stats().kevExposedGapCount).toBe(start.kevExposedGapCount);
      }
    });
  });
}
