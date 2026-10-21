// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// [AC] Technique confirmations go live (Phase 2 design §3 P2-16, E2.1-e; R2,
// R3, §1 fact 20, §6). The three write paths that used to fold a technique
// answer back onto mitigations now write technique marks
// (TechniqueMarksService), so one user action changes every surface by the
// same ref set and changes no mitigation status:
//   - the matrix bulk set writes one 'manual' mark per selected technique;
//   - the drawer's mitigation rows show the D16 badge on an implemented broad
//     mitigation, 'Covered (self-attested, partial via M1038)', with
//     "Confirm for this technique", which writes a 'technique-confirmed' mark
//     (source manual); a confirmed row reads 'Covered (self-attested)' with
//     "Unconfirm", which clears that mark;
//   - the Navigator foreign-comment import writes marks under layer:<name>,
//     replace-by-source.
//
// On the bundled Enterprise 19.2 parsed by the real DataService (fetched once
// from /assets), with the REAL PostureService and stores and POSTURE_TODAY
// pinned. Every surface is read per technique where it has a per-technique
// answer (the posture state, heat=status, heat=covered, the report badge,
// actor-profile's dot) and as counts where it shows counts (stats-bar, the
// posture card, the report split), whose deltas must equal the tally delta of
// the moved refs within each surface's scope (parents only, or with
// sub-techniques on stats-bar).
//
// Precondition (§1.17): M1038 maps 79 techniques (22 parents) in the loaded
// domain; every mitigation of T1059.001 is broader than the threshold 15.
import { HttpClient, provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideLocationMocks } from '@angular/common/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { firstValueFrom, of } from 'rxjs';

import { ActorProfilePanelComponent } from '../components/actor-profile-panel/actor-profile-panel.component';
import { MatrixComponent } from '../components/matrix/matrix.component';
import { PostureCardComponent } from '../components/posture-card/posture-card.component';
import { SidebarComponent } from '../components/sidebar/sidebar.component';
import { StatsBarComponent } from '../components/stats-bar/stats-bar.component';
import type { Domain } from '../models/domain';
import type { Mitigation } from '../models/mitigation';
import type { PostureBucket } from '../models/posture/posture.types';
import { postureBadge } from '../models/posture/posture-vocabulary';
import { computeReportSplit } from '../models/report-split';
import type { Technique } from '../models/technique';
import type { TechniqueRefKey } from '../models/technique-ref';
import { type AttackDomain, DataService } from '../services/data.service';
import { FilterService, type HeatmapMode } from '../services/filter.service';
import { HtmlReportService } from '../services/html-report.service';
import { ImplementationService } from '../services/implementation.service';
import { NavigatorLayerService } from '../services/navigator-layer.service';
import { OwnerDataService } from '../services/owner-data.service';
import { PostureService } from '../services/posture.service';
import { TechniqueMarksService } from '../services/technique-marks.service';
import { ValidationService } from '../services/validation.service';
import { daysBeforeLensToday, lensPostureTodayProvider, resetBrowserState } from './lens-harness';

/** The rung words a fresh profile must never render (§1.3). */
const OWNER_WORDS = /\bcovered\b|\bproven\b|\bdefended\b/i;

type Counts = Record<'covered' | 'partial' | 'proven' | 'stale', number>;

describe('[AC] Technique confirmations go live: drawer Confirm, bulk set and Navigator import (P2-16, E2.1-e)', () => {
  let bundled: Domain;

  beforeAll(async () => {
    const bundle = await (await fetch('assets/data/enterprise-attack.json')).json();
    TestBed.configureTestingModule({ providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }] });
    bundled = (TestBed.inject(DataService) as unknown as { parseBundle(b: unknown, n: string): Domain })
      .parseBundle(bundle, 'Enterprise ATT&CK');
    TestBed.resetTestingModule();
  }, 120_000);

  let matrix: MatrixComponent;
  let filter: FilterService;
  let posture: PostureService;
  let marks: TechniqueMarksService;
  let impl: ImplementationService;

  function boot(): void {
    resetBrowserState();
    TestBed.configureTestingModule({
      imports: [MatrixComponent, SidebarComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), provideLocationMocks(),
        lensPostureTodayProvider(),
      ],
    });
    TestBed.overrideTemplate(MatrixComponent, '');
    const ds = TestBed.inject(DataService) as unknown as {
      attackDomain: AttackDomain; currentDomain$: { next(v: AttackDomain): void }; domainSubject: { next(v: Domain | null): void };
    };
    ds.attackDomain = 'enterprise';
    ds.currentDomain$.next('enterprise');
    ds.domainSubject.next(bundled);
    filter = TestBed.inject(FilterService);
    posture = TestBed.inject(PostureService);
    marks = TestBed.inject(TechniqueMarksService);
    impl = TestBed.inject(ImplementationService);
    const f = TestBed.createComponent(MatrixComponent);
    f.componentRef.setInput('domain', bundled);
    f.componentRef.setInput('attackDomain', 'enterprise');
    f.detectChanges();
    matrix = f.componentInstance;
  }

  afterEach(() => resetBrowserState());

  const tech = (attackId: string): Technique => {
    const t = bundled.techniques.find(x => x.attackId === attackId);
    if (!t) throw new Error(`${attackId} is not in the bundled Enterprise domain`);
    return t;
  };

  /** The loaded mitigation, asserting its breadth (§1.17 precondition). */
  function mitigation(attackId: string, expected: number): Mitigation {
    const m = bundled.mitigations.find(x => x.attackId === attackId);
    const n = m ? bundled.techniquesByMitigation.get(m.id)?.length : undefined;
    if (!m || n !== expected) {
      throw new Error(`Bundled precondition failed: techniquesByMitigation(${attackId}) is ${n}, expected ${expected} (§1.17).`);
    }
    return m;
  }

  // ── Per-technique readers: every surface that answers per technique ───────
  /** One lens's cell per technique, read through the registry projection the matrix binds. */
  function lens(mode: HeatmapMode): (t: Technique) => string {
    filter.setHeatmapMode('frequency');
    filter.setHeatmapMode(mode);
    const read = new Map(bundled.techniques.map(t => {
      const vm = matrix.postureCell(t)!;
      return [t.id, JSON.stringify({ score: vm.score ?? 0, stop: vm.implStop ?? null, label: vm.label })] as const;
    }));
    return (t) => read.get(t.id)!;
  }

  type Reader = (t: Technique) => string;
  /** The per-technique surfaces, read now. */
  function perTechnique(): Record<string, Reader> {
    const html = TestBed.inject(HtmlReportService);
    const actor = TestBed.createComponent(ActorProfilePanelComponent).componentInstance;
    const parse = (s: string) => new DOMParser().parseFromString(s, 'text/html').body.textContent ?? '';
    return {
      posture: t => posture.stateFor(t).bucket,
      statusLens: lens('status'),
      coveredLens: lens('covered'),
      // impl= matches on the guarded view: the status and whether it is partial via a broad mitigation.
      implFilter: t => JSON.stringify([matrix.getTechniqueImplStatus(t), matrix.getImplPartialVia(t)]),
      reportBadge: t => parse(html.techniqueBadge(t)),
      actorProfile: t => actor.getTechCoverage(t),
    };
  }

  /** Every surface's answer for every technique of the loaded domain. */
  function snapshot(): Record<string, Map<string, string>> {
    const out: Record<string, Map<string, string>> = {};
    for (const [name, read] of Object.entries(perTechnique())) {
      out[name] = new Map(bundled.techniques.map(t => [t.attackId, read(t)] as const));
    }
    return out;
  }

  /** The ATT&CK ids whose answer moved, per surface. */
  function movedIds(before: Record<string, Map<string, string>>, after: Record<string, Map<string, string>>): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    for (const name of Object.keys(before)) {
      out[name] = [...before[name].keys()].filter(id => before[name].get(id) !== after[name].get(id)).sort();
    }
    return out;
  }

  // ── Count surfaces ────────────────────────────────────────────────────────
  interface CountSurfaces {
    statsBar: Counts;
    statsBarWithSubs: number;
    card: Counts;
    reportSplit: Counts;
  }

  let statsFixture: ComponentFixture<StatsBarComponent> | null = null;
  let cardFixture: ComponentFixture<PostureCardComponent> | null = null;

  function mountCounts(): void {
    statsFixture = TestBed.createComponent(StatsBarComponent);
    statsFixture.componentRef.setInput('domain', bundled);
    statsFixture.detectChanges();
    statsFixture.componentInstance.toggleSubtechniques();
    statsFixture.detectChanges();
    cardFixture = TestBed.createComponent(PostureCardComponent);
    cardFixture.detectChanges();
  }

  function counts(): CountSurfaces {
    const p = statsFixture!.componentInstance.postureTally();
    const c = cardFixture!.componentInstance.tally();
    const split = computeReportSplit(bundled, posture.rollup(), impl.summarize()['implemented']);
    const four = (x: Counts): Counts => ({ covered: x.covered, partial: x.partial, proven: x.proven, stale: x.stale });
    return { statsBar: four(p), statsBarWithSubs: p.coveredWithSubs, card: four(c), reportSplit: four(split) };
  }

  /** The tally delta of `ids` from `before` to now (posture buckets), within a scope. */
  function bucketDelta(ids: readonly string[], before: Map<string, string>, scope: (t: Technique) => boolean): Counts {
    const d: Counts = { covered: 0, partial: 0, proven: 0, stale: 0 };
    const bump = (b: string, n: number) => { if (b in d) d[b as keyof Counts] += n; };
    for (const id of ids) {
      const t = tech(id);
      if (!scope(t)) continue;
      bump(before.get(id)!, -1);
      bump(posture.stateFor(t).bucket, +1);
    }
    return d;
  }

  const minus = (a: Counts, b: Counts): Counts =>
    ({ covered: a.covered - b.covered, partial: a.partial - b.partial, proven: a.proven - b.proven, stale: a.stale - b.stale });
  const isParent = (t: Technique) => !t.isSubtechnique;

  /** Each count surface moved by exactly the tally delta of `ids` in its scope. */
  function expectCountsMovedBy(ids: readonly string[], before: CountSurfaces, postureBefore: Map<string, string>): void {
    const after = counts();
    const parents = bucketDelta(ids, postureBefore, isParent);
    const all = bucketDelta(ids, postureBefore, () => true);
    expect(minus(after.statsBar, before.statsBar)).withContext('stats-bar (parents)').toEqual(parents);
    expect(minus(after.card, before.card)).withContext('posture card (parents)').toEqual(parents);
    expect(minus(after.reportSplit, before.reportSplit)).withContext('report split (parents)').toEqual(parents);
    expect(after.statsBarWithSubs - before.statsBarWithSubs).withContext('stats-bar incl. sub-techniques').toBe(all.covered);
  }

  function select(ids: readonly string[]): void {
    for (const id of ids) matrix.selectedTechIds.add(tech(id).id);
  }

  // ── Bulk set ──────────────────────────────────────────────────────────────
  describe('matrix bulk set', () => {
    beforeEach(() => boot());

    it("[AC] bulk-set T1059.001 'implemented' moves every surface by exactly {T1059.001} and changes no mitigation status", () => {
      mountCounts();
      const before = snapshot();
      const countsBefore = counts();
      const statusesBefore = [...impl.getStatusMap()];

      select(['T1059.001']);
      matrix.bulkSetStatus('implemented');

      const after = snapshot();
      for (const [name, ids] of Object.entries(movedIds(before, after))) {
        expect(ids).withContext(name).toEqual(['T1059.001']);
      }
      expect(after['posture'].get('T1059.001')).toBe('covered');
      expect(JSON.parse(after['coveredLens'].get('T1059.001')!).score).toBe(2);
      expect(JSON.parse(after['statusLens'].get('T1059.001')!).stop).toBe('implemented');
      expect(after['reportBadge'].get('T1059.001')).toBe('Covered (self-attested)');
      expect(after['actorProfile'].get('T1059.001')).toBe('yes');
      expectCountsMovedBy(['T1059.001'], countsBefore, before['posture']);
      expect(counts().statsBarWithSubs - countsBefore.statsBarWithSubs).withContext('a sub-technique: +1 with subs on').toBe(1);

      expect([...impl.getStatusMap()]).withContext('no mitigation status written').toEqual(statusesBefore);
      expect(statusesBefore).toEqual([]);
      expect(marks.all.map(m => [m.ref, m.status, m.source, m.via ?? null]))
        .toEqual([['attack/enterprise/T1059.001@' + bundled.attackVersion, 'implemented', 'manual', null]]);
      expect(matrix.selectedTechIds.size).withContext('the selection clears').toBe(0);
    });

    it('walk step 3: with M1038 implemented, a bulk set on 3 selected techniques changes exactly those 3 everywhere and no mitigation status', () => {
      const m1038 = mitigation('M1038', 79);
      impl.setStatus(m1038.id, 'implemented');
      const m1038Parents = bundled.techniquesByMitigation.get(m1038.id)!.filter(isParent).map(t => t.attackId).sort();
      const outside = bundled.techniques.filter(t => isParent(t) && !m1038Parents.includes(t.attackId)).map(t => t.attackId).sort();
      // Two partial parents (through M1038) and one parent M1038 does not reach.
      const picked = [m1038Parents[0], m1038Parents[1], outside[0]].sort();
      mountCounts();
      const before = snapshot();
      const countsBefore = counts();
      const statusesBefore = [...impl.getStatusMap()];
      expect([before['posture'].get(m1038Parents[0]), before['posture'].get(m1038Parents[1])]).toEqual(['partial', 'partial']);
      expect(['known', 'none']).toContain(before['posture'].get(outside[0])!);

      select(picked);
      matrix.bulkSetStatus('implemented');

      const after = snapshot();
      for (const [name, ids] of Object.entries(movedIds(before, after))) expect(ids).withContext(name).toEqual(picked);
      for (const id of picked) expect(after['posture'].get(id)).withContext(id).toBe('covered');
      expectCountsMovedBy(picked, countsBefore, before['posture']);
      expect(minus(counts().card, countsBefore.card)).toEqual({ covered: 3, partial: -2, proven: 0, stale: 0 });
      expect([...impl.getStatusMap()]).withContext('the drawer mitigation statuses are unchanged').toEqual(statusesBefore);
      expect(impl.getStatus(m1038.id)).toBe('implemented');
    });

    it("'Clear status' clears the selected techniques' manual marks only", () => {
      select(['T1059.001', 'T1003']);
      matrix.bulkSetStatus('planned');
      expect(marks.all.map(m => [m.ref.split('/')[2].split('@')[0], m.status]).sort()).toEqual([['T1003', 'planned'], ['T1059.001', 'planned']]);
      select(['T1003']);
      matrix.bulkSetStatus(null);
      expect(marks.all.map(m => m.ref.split('/')[2].split('@')[0])).toEqual(['T1059.001']);
      expect(impl.getStatusMap().size).toBe(0);
    });
  });

  // ── Drawer: badge, Confirm and Unconfirm ──────────────────────────────────
  describe('drawer mitigation rows', () => {
    let drawer: ComponentFixture<SidebarComponent>;

    beforeEach(() => {
      boot();
      drawer = TestBed.createComponent(SidebarComponent);
      drawer.detectChanges();
    });

    function open(attackId: string): HTMLElement {
      filter.selectTechnique(tech(attackId));
      drawer.detectChanges();
      if (drawer.componentInstance.isSectionCollapsed('mitigations')) drawer.componentInstance.toggleSection('mitigations');
      drawer.detectChanges();
      return drawer.nativeElement as HTMLElement;
    }

    /** The mitigation row of `mitAttackId` in the open drawer. */
    function row(host: HTMLElement, mitAttackId: string): HTMLElement {
      const li = [...host.querySelectorAll<HTMLElement>('.mitigation-item')]
        .find(el => (el.querySelector('.mit-id')?.textContent ?? '').trim() === mitAttackId);
      expect(li).withContext(`${mitAttackId} row`).toBeDefined();
      return li!;
    }
    const text = (el: Element | null) => (el?.textContent ?? '').trim();

    it('[AC] Confirm on a broad mitigation makes the technique covered on every surface; Unconfirm reverts it (walk steps 1-2)', () => {
      const m1038 = mitigation('M1038', 79);
      // Walk step 1: mark M1038 implemented from the T1059.001 drawer's own row.
      let host = open('T1059.001');
      const chips = [...row(host, 'M1038').querySelectorAll<HTMLButtonElement>('.impl-chip')];
      chips.find(b => text(b).endsWith('Implemented'))!.click();
      drawer.detectChanges();
      expect(impl.getStatus(m1038.id)).toBe('implemented');

      host = drawer.nativeElement as HTMLElement;
      const r = row(host, 'M1038');
      expect(text(r.querySelector('[data-testid="mit-posture-badge"]'))).toBe('Covered (self-attested, partial via M1038)');
      expect(text(r.querySelector('[data-testid="mit-confirm"]'))).toBe('Confirm for this technique');
      expect(r.querySelector('[data-testid="mit-unconfirm"]')).toBeNull();
      // Rows of mitigations that are not implemented carry no badge.
      for (const other of ['M1045', 'M1026', 'M1049', 'M1042']) {
        expect(row(host, other).querySelector('[data-testid="mit-posture-row"]')).withContext(other).toBeNull();
      }
      // heat=covered: 79 partial techniques, 22 parent cells.
      const partial = bundled.techniques.filter(t => posture.stateFor(t).bucket === 'partial');
      expect([partial.length, partial.filter(isParent).length]).toEqual([79, 22]);
      const coveredLens = lens('covered');
      expect(bundled.techniques.filter(t => JSON.parse(coveredLens(t)).score === 1).length).toBe(79);

      mountCounts();
      const before = snapshot();
      const countsBefore = counts();
      const statusesBefore = [...impl.getStatusMap()];

      // Walk step 2: Confirm for T1059.001.
      (r.querySelector('[data-testid="mit-confirm"]') as HTMLButtonElement).click();
      drawer.detectChanges();
      host = drawer.nativeElement as HTMLElement;
      const confirmed = row(host, 'M1038');
      expect(text(confirmed.querySelector('[data-testid="mit-posture-badge"]'))).toBe('Covered (self-attested)');
      expect(text(confirmed.querySelector('[data-testid="mit-unconfirm"]'))).toBe('Unconfirm');
      expect(confirmed.querySelector('[data-testid="mit-confirm"]')).toBeNull();
      expect(marks.all.map(m => [m.ref, m.status, m.source, m.via]))
        .toEqual([['attack/enterprise/T1059.001@' + bundled.attackVersion, 'implemented', 'manual', 'M1038']]);

      const after = snapshot();
      for (const [name, ids] of Object.entries(movedIds(before, after))) expect(ids).withContext(name).toEqual(['T1059.001']);
      expect(after['posture'].get('T1059.001')).toBe('covered');
      expect(JSON.parse(after['coveredLens'].get('T1059.001')!).score).toBe(2);
      expect(JSON.parse(after['statusLens'].get('T1059.001')!).stop).toBe('implemented');
      expect(after['reportBadge'].get('T1059.001')).toBe('Covered (self-attested)');
      expect(after['actorProfile'].get('T1059.001')).toBe('yes');
      expect(bundled.techniques.filter(t => posture.stateFor(t).bucket === 'partial').length).withContext('the other 78 stay partial').toBe(78);
      expectCountsMovedBy(['T1059.001'], countsBefore, before['posture']);
      expect([...impl.getStatusMap()]).withContext('Confirm writes no mitigation status').toEqual(statusesBefore);

      // Unconfirm clears that mark: every surface reads as before.
      (confirmed.querySelector('[data-testid="mit-unconfirm"]') as HTMLButtonElement).click();
      drawer.detectChanges();
      host = drawer.nativeElement as HTMLElement;
      expect(text(row(host, 'M1038').querySelector('[data-testid="mit-posture-badge"]'))).toBe('Covered (self-attested, partial via M1038)');
      expect(marks.all).toEqual([]);
      const reverted = snapshot();
      for (const [name, ids] of Object.entries(movedIds(before, reverted))) expect(ids).withContext(`${name} after Unconfirm`).toEqual([]);
      expect(counts()).toEqual(countsBefore);
      expect(impl.getStatus(m1038.id)).toBe('implemented');
    });

    it('fresh profile: no badge renders and no Covered or Proven word in the mitigation rows', () => {
      const host = open('T1059.001');
      const rows = host.querySelectorAll('.mitigation-item');
      expect(rows.length).withContext('T1059.001 lists its five mitigations').toBe(5);
      expect(host.querySelector('[data-testid="mit-posture-row"]')).toBeNull();
      const list = host.querySelector('.mitigation-list') as HTMLElement;
      const attrs = [...list.querySelectorAll('[title],[aria-label],[placeholder],[alt]')]
        .flatMap(e => ['title', 'aria-label', 'placeholder', 'alt'].map(a => e.getAttribute(a) ?? ''));
      expect([list.textContent ?? '', ...attrs].join(' ')).not.toMatch(OWNER_WORDS);
      expect(posture.ownerWords()).toBeFalse();
    });

    it('a broad mitigation that is only planned renders no badge (only implemented marks are partial)', () => {
      impl.setStatus(mitigation('M1038', 79).id, 'planned');
      const host = open('T1059.001');
      expect(host.querySelector('[data-testid="mit-posture-row"]')).toBeNull();
    });

    // The row's text is postureBadge() of the technique's own state, so the
    // drawer cannot give a second answer when another source covers it (§2.4, §4.1).
    /** The M1038 row of T1059.001: badge text, its partial class and which control it offers. */
    function m1038Row(): { text: string; partial: boolean; confirm: boolean; unconfirm: boolean } {
      const r = row(open('T1059.001'), 'M1038');
      const badge = r.querySelector('[data-testid="mit-posture-badge"]');
      expect(badge).withContext('M1038 badge').not.toBeNull();
      return {
        text: text(badge),
        partial: badge!.classList.contains('partial'),
        confirm: r.querySelector('[data-testid="mit-confirm"]') !== null,
        unconfirm: r.querySelector('[data-testid="mit-unconfirm"]') !== null,
      };
    }
    /** The answer every other surface gives for T1059.001: its state's badge, and the report's. */
    function otherSurfaces(): { state: string; report: string; bucket: string } {
      const t = tech('T1059.001');
      const report = new DOMParser().parseFromString(TestBed.inject(HtmlReportService).techniqueBadge(t), 'text/html').body.textContent ?? '';
      return { state: postureBadge(posture.stateFor(t)), report, bucket: posture.stateFor(t).bucket };
    }
    const t1059001Ref = () => 'attack/enterprise/T1059.001@' + bundled.attackVersion as TechniqueRefKey;

    it('an implemented layer mark makes the row read the covered state the report shows, with no Confirm', () => {
      impl.setStatus(mitigation('M1038', 79).id, 'implemented');
      expect(marks.replaceSource('layer:Vendor A', [{ ref: t1059001Ref(), status: 'implemented' }])).toBe(1);
      const other = otherSurfaces();
      expect(other.bucket).toBe('covered');
      const r = m1038Row();
      expect(r.text).toBe(other.state);
      expect(r.text).toBe(other.report);
      expect(r.text).not.toContain('partial');
      expect(r.partial).toBeFalse();
      expect(r.confirm).withContext('no Confirm on a technique that is already covered').toBeFalse();
      expect(r.unconfirm).withContext('no Unconfirm without a manual mark').toBeFalse();
    });

    it('Unconfirm with a layer mark in place leaves the row on the covered state, not the partial text', () => {
      impl.setStatus(mitigation('M1038', 79).id, 'implemented');
      expect(m1038Row().confirm).toBeTrue();
      (row(open('T1059.001'), 'M1038').querySelector('[data-testid="mit-confirm"]') as HTMLButtonElement).click();
      drawer.detectChanges();
      marks.replaceSource('layer:Vendor A', [{ ref: t1059001Ref(), status: 'implemented' }]);
      let r = m1038Row();
      expect([r.text, r.confirm, r.unconfirm]).toEqual([otherSurfaces().state, false, true]);
      (row(open('T1059.001'), 'M1038').querySelector('[data-testid="mit-unconfirm"]') as HTMLButtonElement).click();
      drawer.detectChanges();
      expect(marks.all.map(m => m.source)).toEqual(['layer:Vendor A']);
      r = m1038Row();
      expect(otherSurfaces().bucket).toBe('covered');
      expect([r.text, r.partial, r.confirm, r.unconfirm]).toEqual([otherSurfaces().state, false, false, false]);
    });

    it('a confirmed technique with a fresh range run reads the proven badge the report shows, still with Unconfirm', () => {
      impl.setStatus(mitigation('M1038', 79).id, 'implemented');
      (row(open('T1059.001'), 'M1038').querySelector('[data-testid="mit-confirm"]') as HTMLButtonElement).click();
      drawer.detectChanges();
      const imported = TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
        { id: 'p2-16-proof', techniqueId: 'T1059.001', runDate: daysBeforeLensToday(10), status: 'passed',
          attackResult: 'executed', detectionsFired: ['sigma:p2-16-proof'] },
      ] }));
      expect(imported.ok).toBeTrue();
      const other = otherSurfaces();
      expect(other.bucket).toBe('proven');
      const r = m1038Row();
      expect(r.text).toBe(other.state);
      expect(r.text).toBe(other.report);
      expect(r.text).not.toBe('Covered (self-attested)');
      expect([r.partial, r.confirm, r.unconfirm]).toEqual([false, false, true]);
    });
  });

  // ── Navigator foreign-comment import ──────────────────────────────────────
  describe('Navigator foreign-comment import', () => {
    beforeEach(() => boot());

    const layer = (name: string, entries: Array<[string, string]>) => JSON.stringify({
      name, domain: 'enterprise-attack', techniques: entries.map(([techniqueID, comment]) => ({ techniqueID, comment })),
    });
    const importLayer = (json: string) => TestBed.inject(NavigatorLayerService).importLayer(
      json, bundled, impl, undefined, { deriveStatusesFromComments: true, attackDomain: 'enterprise' });
    const bySource = () => marks.all.map(m => [m.source, m.ref.split('/')[2].split('@')[0], m.status]).sort();

    it('[AC] a foreign comment marks 1 technique and 0 mitigations; every surface moves by that ref', async () => {
      mountCounts();
      const before = snapshot();
      const countsBefore = counts();
      const result = await importLayer(layer('Vendor A', [['T1059.001', 'Status: implemented']]));
      expect([result.statusesApplied, result.marksApplied]).toEqual([0, 1]);
      expect(result.derivedStatuses).toEqual([{ techniqueId: 'T1059.001', status: 'implemented', comment: 'Status: implemented' }]);
      expect(impl.getStatusMap().size).withContext('0 mitigations (T1059.001 has 5)').toBe(0);
      expect(bySource()).toEqual([['layer:Vendor A', 'T1059.001', 'implemented']]);
      const after = snapshot();
      for (const [name, ids] of Object.entries(movedIds(before, after))) expect(ids).withContext(name).toEqual(['T1059.001']);
      expectCountsMovedBy(['T1059.001'], countsBefore, before['posture']);
    });

    it('re-importing the same layer replaces only its layer:<name> marks', async () => {
      select(['T1003']);
      matrix.bulkSetStatus('implemented');
      await importLayer(layer('Vendor B', [['T1110', 'implemented']]));
      await importLayer(layer('Vendor A', [['T1059.001', 'implemented'], ['T1078', 'in progress']]));
      expect(bySource()).toEqual([
        ['layer:Vendor A', 'T1059.001', 'implemented'], ['layer:Vendor A', 'T1078', 'in-progress'],
        ['layer:Vendor B', 'T1110', 'implemented'], ['manual', 'T1003', 'implemented'],
      ]);
      expect(posture.stateFor(tech('T1059.001')).bucket).toBe('covered');

      // The edited layer no longer mentions T1059.001: its mark goes, the others stay.
      const result = await importLayer(layer('Vendor A', [['T1078', 'planned']]));
      expect(result.marksApplied).toBe(1);
      expect(bySource()).toEqual([
        ['layer:Vendor A', 'T1078', 'planned'], ['layer:Vendor B', 'T1110', 'implemented'], ['manual', 'T1003', 'implemented'],
      ]);
      expect(posture.stateFor(tech('T1059.001')).bucket).not.toBe('covered');
      expect(impl.getStatusMap().size).toBe(0);
    });
  });

  // ── D4 after the write move (Revision 3) ──────────────────────────────────
  describe('D4: the moved writes still count as owner data', () => {
    beforeEach(() => boot());

    const hasOwnerData = () => firstValueFrom(TestBed.inject(OwnerDataService).hasOwnerData$);

    it("an otherwise empty profile: a bulk set of 'implemented' on one technique makes hasOwnerData and ownerWords() true", async () => {
      expect(await hasOwnerData()).toBeFalse();
      expect(posture.ownerWords()).toBeFalse();
      select(['T1059.001']);
      matrix.bulkSetStatus('implemented');
      expect(await hasOwnerData()).toBeTrue();
      expect(posture.ownerWords()).toBeTrue();
      expect(impl.getStatusMap().size).toBe(0);
    });

    it('an otherwise empty profile: a Navigator import with a foreign comment makes hasOwnerData and ownerWords() true', async () => {
      expect(await hasOwnerData()).toBeFalse();
      expect(posture.ownerWords()).toBeFalse();
      await TestBed.inject(NavigatorLayerService).importLayer(
        JSON.stringify({ name: 'Vendor A', techniques: [{ techniqueID: 'T1059.001', comment: 'implemented' }] }),
        bundled, impl, undefined, { deriveStatusesFromComments: true, attackDomain: 'enterprise' });
      expect(await hasOwnerData()).toBeTrue();
      expect(posture.ownerWords()).toBeTrue();
      expect(impl.getStatusMap().size).toBe(0);
    });

    it("a bulk set of 'planned' alone is not owner data (D4 counts implemented marks only)", async () => {
      select(['T1059.001']);
      matrix.bulkSetStatus('planned');
      expect(await hasOwnerData()).toBeFalse();
      expect(posture.ownerWords()).toBeFalse();
    });
  });
});
