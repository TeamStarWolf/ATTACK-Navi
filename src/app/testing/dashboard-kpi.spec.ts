// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization of the dashboard KPIs on the fixed fixture domain. Every
// expected number is recomputed here by an independent oracle from the fixture
// and the stub signal data (lens-harness.ts), then checked twice: on the
// component's `stats` and on the rendered Coverage Summary widget.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { DashboardPanelComponent } from '../components/dashboard-panel/dashboard-panel.component';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { DataService } from '../services/data.service';
import { ImplementationService } from '../services/implementation.service';
import {
  IMPL_CYCLE, controlsProvider, cvesFor, parseFixtureDomain, resetBrowserState, signal,
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

  it('counts parent techniques only, and coverage = any of the seven signal families', () => {
    const stats = fixture.componentInstance.stats!;
    expect(stats.totalTechniques).toBe(45);
    expect(stats.coveredTechniques).toBe(count(o => o.enriched));
    expect(stats.uncoveredCount).toBe(45 - stats.coveredTechniques);
    expect(stats.coveragePct).toBe(pct(stats.coveredTechniques));
    expect(stats.mitigationCoveragePct).toBe(pct(count(o => o.mitigation)));
    expect(stats.controlCoveragePct).toBe(pct(count(o => o.control)));
  });

  it('detection coverage is CAR analytics / Atomic / D3FEND (not Sigma)', () => {
    const stats = fixture.componentInstance.stats!;
    expect(stats.withCarCount).toBe(count(o => o.car));
    expect(stats.withAtomicCount).toBe(count(o => o.atomic));
    expect(stats.withD3fendCount).toBe(count(o => o.d3fend));
    expect(stats.detectionCoveragePct).toBe(pct(count(o => o.car || o.atomic || o.d3fend)));
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

  it('posture score follows the documented 20/20/20/15/15/10 weighting', () => {
    const stats = fixture.componentInstance.stats!;
    const f = (n: number) => n / parents.length;
    const kevGaps = count(o => o.kev && !o.defended);
    const critical = count(o => o.groups > 0 && !o.defended);
    const expected = Math.round(100 * (
      0.20 * f(count(o => o.mitigation)) +
      0.20 * f(count(o => o.detection)) +
      0.20 * f(count(o => o.control)) +
      0.15 * f(count(o => o.d3fend)) +
      0.15 * (1 - f(kevGaps)) +
      0.10 * (1 - f(critical))
    ));
    expect(stats.postureScore).toBe(expected);
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

  it('renders the headline KPIs in the Coverage Summary widget', () => {
    const stats = fixture.componentInstance.stats!;
    expect(rendered('Total Techniques')).toBe('45');
    expect(rendered('Enriched')).toBe(String(stats.coveredTechniques));
    expect(rendered('Coverage')).toBe(`${stats.coveragePct}%`);
    expect(rendered('Mitigation coverage')).toBe(`${stats.mitigationCoveragePct}%`);
    expect(rendered('Control coverage')).toBe(`${stats.controlCoveragePct}%`);
    // E1.5: the composite is shown as a Known-rung 'Reference depth index', not a 'Posture score'.
    expect(rendered('Reference depth index')).toBe(String(stats.postureScore));
    expect(rendered('Posture score')).toBe('(not rendered)');
  });
});
