// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.7 equality spec: the seven summary surfaces (stats-bar, tactic-summary,
// analytics-panel, timeline-panel, coverage-diff-panel, roadmap-panel and,
// since the post-Phase-1 QA sweep (R9a), dashboard-panel) show the
// SAME Known-tier 'mapped' count for the same filter, read off what each one
// renders, and none of them moves when a group starts using a technique.
//
// The expected number comes from an independent oracle over the fixture domain
// and the stub signal data (lens-harness.ts): a technique is mapped when it has
// at least one defensive reference input (mitigation, Sigma/CAR detection
// content, a CTID control mapping, a D3FEND countermeasure or an Atomic test).
// Threat-intel links and CVE mappings are deliberately not inputs.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Type } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { Domain, TacticColumn } from '../models/domain';
import { Technique } from '../models/technique';
import { DataService } from '../services/data.service';
import { EnrichmentService } from '../services/enrichment.service';
import { TimelineService, CoverageSnapshot } from '../services/timeline.service';
import { StatsBarComponent } from '../components/stats-bar/stats-bar.component';
import { TacticSummaryComponent } from '../components/tactic-summary/tactic-summary.component';
import { AnalyticsPanelComponent } from '../components/analytics-panel/analytics-panel.component';
import { TimelinePanelComponent } from '../components/timeline-panel/timeline-panel.component';
import { CoverageDiffPanelComponent } from '../components/coverage-diff-panel/coverage-diff-panel.component';
import { RoadmapPanelComponent } from '../components/roadmap-panel/roadmap-panel.component';
import { DashboardPanelComponent } from '../components/dashboard-panel/dashboard-panel.component';
import { controlsProvider, cvesFor, parseFixtureDomain, resetBrowserState, signal, signalStubProviders } from './lens-harness';

/** Known tier, straight from the stubs: >=1 defensive reference input. */
function oracleMapped(t: Technique): boolean {
  const id = t.attackId;
  return (
    t.mitigationCount > 0 ||
    signal('sigma', id) + signal('car-live', id) > 0 ||
    signal('nist', id) + signal('cri', id) + signal('cis', id) + signal('csa', id) + signal('m365-ctl', id) > 0 ||
    signal('d3fend', id) > 0 ||
    signal('atomic', id) > 0
  );
}

/** The old isEnriched() answer: the oracle plus threat-intel and CVE links. */
function oracleEnriched(t: Technique, d: Domain): boolean {
  const threat =
    (d.groupsByTechnique.get(t.id)?.length ?? 0) +
    (d.softwareByTechnique.get(t.id)?.length ?? 0) +
    (d.campaignsByTechnique.get(t.id)?.length ?? 0);
  return oracleMapped(t) || threat > 0 || cvesFor(t.attackId).length > 0;
}

const text = (el: Element | null | undefined) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();

/** "12 / 45" or "12/45" anywhere in a string, as [mapped, total]. */
function fraction(s: string): [number, number] {
  const m = /(\d+)\s*\/\s*(\d+)/.exec(s);
  if (!m) throw new Error(`no "n / m" in: ${s}`);
  return [Number(m[1]), Number(m[2])];
}

/** What each surface renders for the overall (parent-technique) mapped count. */
interface Rendered { mapped: number; total: number; pct?: number }

describe('Known-tier mapped count: the seven summary surfaces agree (E1.7 equality spec)', () => {
  let domain: Domain;
  let parents: Technique[];

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    parents = domain.techniques.filter(t => !t.isSubtechnique);
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        controlsProvider(domain),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
  });

  afterEach(() => resetBrowserState());

  function create<T>(type: Type<T>): ComponentFixture<T> {
    const f = TestBed.createComponent(type);
    f.detectChanges();
    return f;
  }

  const el = (f: ComponentFixture<unknown>) => f.nativeElement as HTMLElement;

  // ── One reader per surface, all reading the rendered DOM ──────────────────

  function statsBar(): { overall: Rendered; byTactic: Map<string, [number, number]> } {
    const f = TestBed.createComponent(StatsBarComponent);
    f.componentRef.setInput('domain', domain);
    f.detectChanges();
    const [mapped, total] = fraction(text(el(f).querySelector('.coverage-sub')));
    const pct = Number(text(el(f).querySelector('.big-num')).replace('%', ''));
    const byTactic = new Map<string, [number, number]>();
    for (const bar of Array.from(el(f).querySelectorAll('.tactic-stat'))) {
      const title = bar.getAttribute('title') ?? '';
      byTactic.set(title.slice(0, title.indexOf(':')), fraction(title));
    }
    expect(text(el(f).querySelector('.big-label'))).toBe('Mapped');
    return { overall: { mapped, total, pct }, byTactic };
  }

  function tacticSummary(col: TacticColumn): [number, number, number] {
    const f = create(TacticSummaryComponent);
    const all = col.techniques.flatMap(t => [t, ...(t.subtechniques ?? [])]);
    f.componentInstance.show(
      { tactic: col.tactic, techniques: all, parentTechniques: col.techniques, domain },
      new MouseEvent('click', { clientX: 10, clientY: 10 }),
    );
    f.detectChanges();
    const row = Array.from(el(f).querySelectorAll('.stat-row'))
      .find(r => text(r.querySelector('.stat-label')) === 'Mapped');
    const value = text(row?.querySelector('.stat-value'));
    const [mapped, total] = fraction(value);
    const pct = Number(/\((\d+)%\)/.exec(value)?.[1] ?? NaN);
    f.destroy();
    return [mapped, total, pct];
  }

  function analytics(): { overall: Rendered; byTactic: Map<string, [number, number]> } {
    const f = create(AnalyticsPanelComponent);
    const card = Array.from(el(f).querySelectorAll('.stat-card'))
      .find(c => text(c.querySelector('.stat-label')) === 'Techniques Mapped');
    const [mapped, total] = fraction(text(card?.querySelector('.stat-big')));
    const pct = Number(text(el(f).querySelector('.donut-value')).replace('%', ''));
    const byTactic = new Map<string, [number, number]>();
    for (const row of Array.from(el(f).querySelectorAll('.tactic-row'))) {
      byTactic.set(row.querySelector('.tactic-name')?.getAttribute('title') ?? '', fraction(text(row.querySelector('.tactic-counts'))));
    }
    return { overall: { mapped, total, pct }, byTactic };
  }

  /** Takes a snapshot through the timeline panel's own button path and reads its card. */
  function timeline(label: string): { overall: Rendered; snapshot: CoverageSnapshot } {
    const f = create(TimelinePanelComponent);
    f.componentInstance.newLabel = label;
    f.componentInstance.takeSnapshot();
    f.detectChanges();
    const [mapped, total] = fraction(text(el(f).querySelector('.snapshot-card .card-sub')));
    const pct = Number(text(el(f).querySelector('.snapshot-card .coverage-pct')).replace('%', ''));
    const snapshot = TestBed.inject(TimelineService).getLatest()!;
    f.destroy();
    return { overall: { mapped, total, pct }, snapshot };
  }

  /** Coverage diff of the first and latest snapshots: "a → b" techniques mapped, per tactic rows. */
  function coverageDiff(): { base: number; compare: number; byTactic: Map<string, [number, number]> } {
    const f = create(CoverageDiffPanelComponent);
    const card = Array.from(el(f).querySelectorAll('.hero-card'))
      .find(c => text(c.querySelector('.hero-label')) === 'Techniques Mapped');
    const m = /(\d+)\s*→\s*(\d+)/.exec(text(card?.querySelector('.hero-from')));
    const byTactic = new Map<string, [number, number]>();
    for (const row of Array.from(el(f).querySelectorAll('.tac-row'))) {
      byTactic.set(text(row.querySelector('.tac-name')), fraction(text(row.querySelector('.tac-comp'))));
    }
    f.destroy();
    return { base: Number(m?.[1]), compare: Number(m?.[2]), byTactic };
  }

  function roadmap(): Rendered {
    const f = create(RoadmapPanelComponent);
    const known = el(f).querySelector('[data-testid="roadmap-mapped"]');
    const [mapped, total] = fraction(text(known?.querySelector('strong')));
    const pct = Number(/\((\d+)%\)/.exec(text(known))?.[1] ?? NaN);
    f.destroy();
    return { mapped, total, pct };
  }

  /** Dashboard Mapped Summary tiles and Tactic Breakdown rows (R9a). */
  function dashboard(): { overall: Rendered; byTactic: Map<string, [number, number]> } {
    const f = create(DashboardPanelComponent);
    const tile = (label: string) => text(Array.from(el(f).querySelectorAll('.widget-coverage-summary .mini-stat'))
      .find(s => text(s.querySelector('.mini-stat-label')) === label)?.querySelector('.mini-stat-value'));
    const overall = {
      mapped: Number(tile('Techniques mapped')),
      total: Number(tile('Total Techniques')),
      pct: Number(tile('Mapped').replace('%', '')),
    };
    const byTactic = new Map<string, [number, number]>();
    for (const row of Array.from(el(f).querySelectorAll('.tactic-bar-row'))) {
      byTactic.set(text(row.querySelector('.tactic-name')), fraction(text(row.querySelector('.tactic-counts'))));
    }
    f.destroy();
    return { overall, byTactic };
  }

  // ── The specs ─────────────────────────────────────────────────────────────

  it('all seven surfaces show the oracle mapped count over parent techniques, and it is not the isEnriched count', () => {
    const expected = parents.filter(oracleMapped).length;
    const enriched = parents.filter(t => oracleEnriched(t, domain)).length;
    const total = parents.length;
    const pct = Math.round((expected / total) * 100);
    // The fixture has threat-only techniques, so the switch is observable.
    expect(enriched).toBeGreaterThan(expected);
    expect(TestBed.inject(EnrichmentService).mappedRollup(domain).overall).toEqual({ total, mapped: expected, pct });

    const tl1 = timeline('Baseline');
    const tl2 = timeline('Later');
    const shown: Record<string, Rendered> = {
      'stats-bar': statsBar().overall,
      'analytics-panel': analytics().overall,
      'timeline-panel': tl2.overall,
      'roadmap-panel': roadmap(),
      'dashboard-panel': dashboard().overall,
    };
    for (const [surface, r] of Object.entries(shown)) {
      expect(r).withContext(surface).toEqual({ mapped: expected, total, pct });
    }
    expect(tl1.snapshot.basis).toBe('reference-mapped');
    const diff = coverageDiff();
    expect([diff.base, diff.compare]).withContext('coverage-diff-panel').toEqual([expected, expected]);

    // tactic-summary has no overall figure; its per-tactic counts must sum to
    // the stats-bar's per-tactic counts (checked tactic by tactic below).
    const summed = domain.tacticColumns.map(c => tacticSummary(c)[0]).reduce((a, b) => a + b, 0);
    const oracleSummed = domain.tacticColumns.reduce((a, c) => a + c.techniques.filter(oracleMapped).length, 0);
    expect(summed).withContext('tactic-summary, summed over tactics').toBe(oracleSummed);
  });

  it('per tactic, stats-bar, tactic-summary, analytics-panel, the timeline snapshot, coverage-diff and the dashboard agree', () => {
    timeline('A');
    const { snapshot } = timeline('B');
    const sb = statsBar().byTactic;
    const an = analytics().byTactic;
    const diff = coverageDiff().byTactic;
    const dash = dashboard().byTactic;
    expect(dash.size).withContext('dashboard tactic rows').toBe(domain.tacticColumns.length);
    expect(domain.tacticColumns.length).toBeGreaterThan(5);
    for (const col of domain.tacticColumns) {
      const name = col.tactic.name;
      const expected: [number, number] = [col.techniques.filter(oracleMapped).length, col.techniques.length];
      const [m, t, p] = tacticSummary(col);
      const snap = snapshot.tacticCoverage.find(x => x.tacticId === col.tactic.id)!;
      expect(sb.get(name)).withContext(`stats-bar ${name}`).toEqual(expected);
      expect([m, t]).withContext(`tactic-summary ${name}`).toEqual(expected);
      expect(an.get(name)).withContext(`analytics-panel ${name}`).toEqual(expected);
      expect([snap.covered, snap.total]).withContext(`timeline snapshot ${name}`).toEqual(expected);
      expect(diff.get(name)).withContext(`coverage-diff-panel ${name}`).toEqual(expected);
      expect(dash.get(name)).withContext(`dashboard-panel ${name}`).toEqual(expected);
      expect(p).withContext(`tactic-summary % ${name}`).toBe(snap.pct);
    }
  });

  it('the stats-bar sub-technique filter changes its total, and the rollup gives the same answer for that filter', () => {
    const f = TestBed.createComponent(StatsBarComponent);
    f.componentRef.setInput('domain', domain);
    f.detectChanges();
    f.componentInstance.toggleSubtechniques();
    f.detectChanges();
    const [mapped, total] = fraction(text(el(f).querySelector('.coverage-sub')));
    expect(total).toBe(domain.techniques.length);
    expect(mapped).toBe(domain.techniques.filter(oracleMapped).length);
    expect(TestBed.inject(EnrichmentService).mappedRollup(domain, { includeSubtechniques: true }).overall.mapped).toBe(mapped);
  });

  it('adding a group, software and campaign that use every technique changes no surface\'s mapped count', () => {
    timeline('Before');
    const before = {
      stats: statsBar(), analytics: analytics(), roadmap: roadmap(), dashboard: dashboard(),
      tactics: domain.tacticColumns.map(c => tacticSummary(c)),
    };
    const enrichment = TestBed.inject(EnrichmentService);
    const threatBefore = enrichment.totals(parents, domain).threatIntel;

    const group = { ...domain.groups[0], id: 'intrusion-set--e17-new-group', attackId: 'G9999', name: 'E1.7 new group' };
    for (const t of domain.techniques) {
      domain.groupsByTechnique.set(t.id, [...(domain.groupsByTechnique.get(t.id) ?? []), group]);
      domain.softwareByTechnique.set(t.id, [...(domain.softwareByTechnique.get(t.id) ?? []), domain.software[0]]);
      domain.campaignsByTechnique.set(t.id, [...(domain.campaignsByTechnique.get(t.id) ?? []), ...domain.campaigns.slice(0, 1)]);
    }
    // Control: the threat links really were added, and the Threat-side answer sees them.
    expect(threatBefore).toBeLessThan(parents.length);
    expect(enrichment.totals(parents, domain).threatIntel).toBe(parents.length);
    expect(parents.filter(t => oracleEnriched(t, domain)).length).toBe(parents.length);

    const { snapshot } = timeline('After');
    expect(statsBar()).toEqual(before.stats);
    expect(analytics()).toEqual(before.analytics);
    expect(roadmap()).toEqual(before.roadmap);
    expect(dashboard()).toEqual(before.dashboard);
    expect(domain.tacticColumns.map(c => tacticSummary(c))).toEqual(before.tactics);
    const diff = coverageDiff();
    expect(diff.compare).withContext('coverage-diff after vs before').toBe(diff.base);
    expect(snapshot.coveredTechniques).toBe(before.stats.overall.mapped);
  });

  it('a snapshot saved before E1.7 (mitigations only) is labelled, kept out of the trend and flagged in the diff', () => {
    const legacy: CoverageSnapshot = {
      id: 'legacy-1', label: 'Old', createdAt: '2026-01-01T00:00:00.000Z',
      totalTechniques: parents.length, coveredTechniques: 3, coveragePct: 7,
      implCounts: { implemented: 0, inProgress: 0, planned: 0, notStarted: 0 },
      tacticCoverage: [], notes: '',
    };
    // TimelineService reads storage when it is first created, which is below.
    localStorage.setItem('mitre-nav-timeline-v1', JSON.stringify([legacy]));

    timeline('New');
    const tl = create(TimelinePanelComponent);
    const subs = Array.from(el(tl).querySelectorAll('.snapshot-card .card-sub')).map(text);
    expect(subs[0]).toContain('techniques mapped');
    expect(subs[1]).toContain('older snapshot: mitigations only');
    expect(el(tl).querySelectorAll('.snapshot-card .delta-badge').length).withContext('no delta across bases').toBe(0);

    const sb = TestBed.createComponent(StatsBarComponent);
    sb.componentRef.setInput('domain', domain);
    sb.detectChanges();
    expect(sb.componentInstance.hasTrend).withContext('one snapshot on the mapped basis is not a trend').toBeFalse();

    const diff = create(CoverageDiffPanelComponent);
    expect(diff.componentInstance.basesDiffer).toBeTrue();
    expect(text(el(diff).querySelector('.cdp-basis-note'))).toContain('different bases');
    // No signed or coloured delta presented as progress across bases: hero cards and tactic rows.
    const diffEl = el(diff);
    expect(diffEl.querySelectorAll('.hero-card.positive, .hero-card.negative').length).withContext('hero cards').toBe(0);
    const heroValues = Array.from(diffEl.querySelectorAll('.hero-card .hero-value')).map(text);
    expect(heroValues).toEqual(['bases differ', 'bases differ']);
    expect(heroValues.some(v => /[+-]\d/.test(v))).toBeFalse();
    const tacRows = Array.from(diffEl.querySelectorAll('.tac-row'));
    expect(tacRows.length).toBeGreaterThan(0);
    expect(diffEl.querySelectorAll('.tac-row.improved, .tac-row.declined, .tac-delta.pos, .tac-delta.neg, .bar-fill').length)
      .withContext('tactic rows').toBe(0);
    for (const row of tacRows) {
      expect(text(row.querySelector('.tac-delta'))).toBe('bases differ');
    }

    // Trends tab: the older bar says its basis; the row after a change of basis is not a 'baseline'.
    const tr = create(TimelinePanelComponent);
    tr.componentInstance.setTab('trends');
    tr.detectChanges();
    const bars = Array.from(el(tr).querySelectorAll('.bar-chart .bar-fill')).map(b => b.getAttribute('title') ?? '');
    expect(bars[0]).toContain('(mitigations only (older snapshot))');
    expect(bars[1]).toContain('(mapped (defensive reference inputs))');
    const deltas = Array.from(el(tr).querySelectorAll('.trends-row')).map(r => text(r.lastElementChild));
    expect(deltas).toEqual(['baseline', 'bases differ']);
  });
});
