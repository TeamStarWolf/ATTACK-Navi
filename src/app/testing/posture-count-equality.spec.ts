// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// [AC] Posture count equality (Phase 2 design §3 P2-07, E2.1-d1; R2, R3, R9,
// R10, R16, S6, S12). It replaces the P2-01 characterization spec
// legacy-implemented-equality.spec.ts, retired in this PR: the legacy
// "implemented technique" answer is gone from every count surface, and the
// before values it pinned stay in __snapshots__/legacy-baseline.json
// (implementedEquality, actorProfileGroups) as the "before" side printed here.
//
// On the lens fixture (lens-harness.ts) parsed by the real DataService, with
// the REAL PostureService and its stores and POSTURE_TODAY pinned to
// 2026-10-01, the seeded profile holds:
//   - M1047 implemented (13 techniques, narrow: full marks),
//   - M1026 implemented (16 techniques, broad: partial marks, D16),
//   - one technique confirmed through TechniqueMarksService.confirm,
//   - one passed own run with a fired detection (Proven),
//   - one failed run after a mark (contradicted),
//   - one not-reproducible run (R16: out of `assessable` only).
// Every count surface must then show the same Known, Covered, partial, Proven
// and stale numbers, subs off: the CTEM posture card (the Home stand-in), the
// Validation panel summary (the Detect > Coverage stand-in), the executive
// report split (HTML and PDF inputs, and the Report Builder) and stats-bar.
// The surfaces are read from the DOM through their data-posture attributes.
// Denominators (R16, §2.2): Known divides by `total`, every Covered share by
// `assessable` (total minus excluded); each surface renders its Covered
// denominator as data-posture="assessable" and its share as data-share-pct.
//
// The last describe is the seam grep (§4.2): stats-bar, report-split and
// actor-profile-panel no longer match both posture-rollup regexes. It reads
// the sources as text at build time (the Angular builder's `loader: 'text'`
// import attribute). tsconfig targets ES2022 modules, so TypeScript reports the
// import attribute (TS2823) and the missing default export of a module read as
// text (TS1192); each expect-error directive covers exactly those on its line.
import { Type, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';

import BASELINE from './__snapshots__/legacy-baseline.json';
import type { Domain } from '../models/domain';
import type { Mitigation } from '../models/mitigation';
import type { Technique } from '../models/technique';
import type { PostureBucket, PostureState } from '../models/posture/posture.types';
import { POSTURE_TODAY } from '../models/posture/posture-today';
import { postureBadge } from '../models/posture/posture-vocabulary';
import { type TechniqueRefKey, refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { computeReportSplit } from '../models/report-split';
import { type AttackDomain, DataService } from '../services/data.service';
import { EnrichmentService } from '../services/enrichment.service';
import { ImplementationService } from '../services/implementation.service';
import { PostureService } from '../services/posture.service';
import { TechniqueMarksService } from '../services/technique-marks.service';
import { ValidationService } from '../services/validation.service';
import { HtmlReportService } from '../services/html-report.service';
import { PdfReportService } from '../services/pdf-report.service';
import { AssetInventoryService } from '../services/asset-inventory.service';
import { Cve2CapecService } from '../services/cve2capec.service';
import { CtemPageComponent } from '../pages/exposure/ctem-page.component';
import { ValidationPanelComponent } from '../components/validation-panel/validation-panel.component';
import { ReportPanelComponent } from '../components/report-panel/report-panel.component';
import { StatsBarComponent } from '../components/stats-bar/stats-bar.component';
import { ActorProfilePanelComponent, type TechMark } from '../components/actor-profile-panel/actor-profile-panel.component';
import { assetExposure, parseFixtureDomain, resetBrowserState, signal as fixtureSignal, signalStubProviders } from './lens-harness';

// @ts-expect-error -- TS2823/TS1192: read as text through the Angular builder's loader import attribute
import STATS_BAR_SRC from '../components/stats-bar/stats-bar.component' with { loader: 'text' };
// @ts-expect-error -- TS2823/TS1192: read as text through the Angular builder's loader import attribute
import REPORT_SPLIT_SRC from '../models/report-split' with { loader: 'text' };
// @ts-expect-error -- TS2823/TS1192: read as text through the Angular builder's loader import attribute
import ACTOR_PROFILE_SRC from '../components/actor-profile-panel/actor-profile-panel.component' with { loader: 'text' };
// @ts-expect-error -- TS2823/TS1192: read as text through the Angular builder's loader import attribute
import HTML_REPORT_SRC from '../services/html-report.service' with { loader: 'text' };

const TODAY = new Date('2026-10-01T00:00:00.000Z');
const daysBefore = (n: number) => new Date(TODAY.getTime() - n * 86_400_000).toISOString();

/** The rung words a fresh profile must never render (§1.3; e2e journey 4 bans the first two). */
const OWNER_WORDS = /\bcovered\b|\bproven\b|\bdefended\b/i;

/** The report-builder CSV cell and the actor-profile row dot for each bucket (P2-07). */
const CSV_CELL: Readonly<Record<PostureBucket, string>> = {
  covered: 'Yes', proven: 'Yes', stale: 'Yes', partial: 'Partial', known: 'No', none: 'No',
};
const ROW_DOT: Readonly<Record<PostureBucket, TechMark>> = {
  covered: 'yes', proven: 'yes', stale: 'yes', partial: 'partial', known: 'no', none: 'no',
};

/**
 * What one surface shows. Covered words are absent on a fresh profile.
 * `assessable` is the Covered denominator a surface renders (R16: total minus
 * excluded), read from its data-posture="assessable" element.
 */
interface Shown {
  mapped: number;
  total: number;
  assessable?: number;
  covered?: number;
  partial?: number;
  proven?: number;
  stale?: number;
}

function readShown(root: ParentNode): Shown {
  const n = (key: string): number | undefined => {
    const el = root.querySelector(`[data-posture="${key}"]`);
    return el ? Number((el.textContent ?? '').trim()) : undefined;
  };
  const out: Shown = { mapped: n('known-mapped') ?? NaN, total: n('known-total') ?? NaN };
  for (const key of ['assessable', 'covered', 'partial', 'proven', 'stale'] as const) {
    const v = n(key);
    if (v !== undefined) out[key] = v;
  }
  return out;
}

/** Visible text plus the attributes the e2e fresh scan reads. */
function renderedWords(root: Element): string {
  const attrs = Array.from(root.querySelectorAll('[title],[aria-label],[placeholder],[alt]'))
    .flatMap(e => ['title', 'aria-label', 'placeholder', 'alt'].map(a => e.getAttribute(a) ?? ''));
  return [root.textContent ?? '', ...attrs].join(' ');
}

const parse = (html: string): Document => new DOMParser().parseFromString(html, 'text/html');

/** The seeded profile's picks, derived from the loaded fixture (not hard-coded). */
interface Seed {
  m1047: Mitigation;
  m1026: Mitigation;
  m1047Parents: string[];
  m1026Parents: string[];
  proof: Technique;
  failed: Technique;
  confirmed: Technique;
  notReproducible: Technique;
}

describe('[AC] Posture count equality across the count surfaces (P2-07, E2.1-d1)', () => {
  let domain: Domain;
  let parents: Technique[];
  let posture: PostureService;

  function load(d: Domain, id: AttackDomain): void {
    const ds = TestBed.inject(DataService) as unknown as {
      attackDomain: AttackDomain; currentDomain$: { next(v: AttackDomain): void }; domainSubject: { next(v: Domain | null): void };
    };
    ds.attackDomain = id;
    ds.currentDomain$.next(id);
    ds.domainSubject.next(d);
  }

  function boot(): void {
    resetBrowserState();
    domain = parseFixtureDomain();
    parents = domain.techniques.filter(t => !t.isSubtechnique);
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        // The CTEM board also reads the asset list and the CVE kill-chain count.
        { provide: AssetInventoryService, useValue: {
          exposureMap$: new BehaviorSubject(assetExposure()), assets$: new BehaviorSubject([]), getExposureDetails: () => [],
        } },
        { provide: Cve2CapecService, useValue: {
          loaded$: of(true), covered$: of(0), getChainCount: (id: string) => fixtureSignal('kill-chain', id),
        } },
        { provide: POSTURE_TODAY, useValue: signal(TODAY) },
      ],
    });
    load(domain, 'enterprise');
    posture = TestBed.inject(PostureService);
  }

  afterEach(() => resetBrowserState());

  const keyOf = (t: Pick<Technique, 'attackId'>): TechniqueRefKey => techniqueRefKey(refForTechnique(t, 'enterprise', domain.attackVersion));
  const tech = (attackId: string): Technique => domain.techniques.find(t => t.attackId === attackId)!;

  /** The loaded mitigation, asserting its breadth (§1.17 precondition). */
  function mitigation(attackId: string, expected: number): Mitigation {
    const m = domain.mitigations.find(x => x.attackId === attackId)!;
    expect(domain.techniquesByMitigation.get(m.id)?.length).withContext(`${attackId} breadth (§1.17)`).toBe(expected);
    return m;
  }
  const parentIds = (m: Mitigation): string[] =>
    (domain.techniquesByMitigation.get(m.id) ?? []).filter(t => !t.isSubtechnique).map(t => t.attackId).sort();

  function picks(): Seed {
    const m1047 = mitigation('M1047', 13);
    const m1026 = mitigation('M1026', 16);
    const m1047Parents = parentIds(m1047);
    const m1026Parents = parentIds(m1026);
    const only1047 = m1047Parents.filter(id => !m1026Parents.includes(id));
    const only1026 = m1026Parents.filter(id => !m1047Parents.includes(id));
    const untouched = parents.map(t => t.attackId).sort().filter(id => !m1047Parents.includes(id) && !m1026Parents.includes(id));
    expect(only1047.length).toBeGreaterThanOrEqual(2);
    expect(only1026.length).toBeGreaterThanOrEqual(1);
    return {
      m1047, m1026, m1047Parents, m1026Parents,
      proof: tech(only1047[0]), failed: tech(only1047[1]), confirmed: tech(only1026[0]), notReproducible: tech(untouched[0]),
    };
  }

  /** Seed the profile through the real stores. */
  function seed(s: Seed, full: boolean): void {
    const impl = TestBed.inject(ImplementationService);
    impl.setStatus(s.m1047.id, 'implemented');
    impl.setStatus(s.m1026.id, 'implemented');
    if (!full) return;
    expect(TestBed.inject(TechniqueMarksService).confirm(keyOf(s.confirmed))).toBeTrue();
    const result = TestBed.inject(ValidationService).importJson(JSON.stringify({ runs: [
      { id: 'p207-pass', techniqueId: s.proof.attackId, runDate: daysBefore(10), status: 'passed', attackResult: 'executed',
        detectionsFired: ['sigma:p2-07'] },
      { id: 'p207-fail', techniqueId: s.failed.attackId, runDate: daysBefore(5), status: 'failed', attackResult: 'executed' },
      { id: 'p207-nr', techniqueId: s.notReproducible.attackId, runDate: daysBefore(3), status: 'not-reproducible', attackResult: 'executed' },
    ] }));
    expect(result.ok).withContext('runs imported').toBeTrue();
  }

  // ── Surfaces ──────────────────────────────────────────────────────────────
  function create<T>(type: Type<T>): ComponentFixture<T> {
    const f = TestBed.createComponent(type);
    f.detectChanges();
    return f;
  }

  interface Surfaces {
    ctem: Shown;
    validation: Shown;
    reportBuilder: Shown;
    htmlReport: Shown;
    pdfReport: Shown;
    statsBar: Shown;
    words: Record<string, string>;
    htmlDoc: Document;
    pdfDoc: Document;
    statsEl: HTMLElement;
    reportBuilderFixture: ComponentFixture<ReportPanelComponent>;
  }

  function surfaces(): Surfaces {
    const ctem = create(CtemPageComponent);
    const card = ctem.nativeElement.querySelector('app-posture-card') as HTMLElement;
    expect(card).withContext('the posture card is mounted in ctem-page').not.toBeNull();

    const validation = create(ValidationPanelComponent);
    const summary = validation.nativeElement.querySelector('.vp-posture app-posture-card') as HTMLElement;
    expect(summary).withContext('the Validation summary header shows the posture card').not.toBeNull();

    const builder = create(ReportPanelComponent);
    const builderGrid = builder.nativeElement.querySelector('.summary-grid') as HTMLElement;

    const stats = TestBed.createComponent(StatsBarComponent);
    stats.componentRef.setInput('domain', domain);
    stats.detectChanges();

    const statusMap = TestBed.inject(ImplementationService).getStatusMap();
    const html = (TestBed.inject(HtmlReportService) as unknown as {
      buildHtml(d: Domain, m: ReadonlyMap<string, unknown>): string;
    }).buildHtml(domain, statusMap);
    const pdf = (TestBed.inject(PdfReportService) as unknown as {
      buildReportHtml(d: Domain, m: ReadonlyMap<string, unknown>): string;
    }).buildReportHtml(domain, statusMap);
    const htmlDoc = parse(html);
    const pdfDoc = parse(pdf);
    // The HTML report: Known in the split block, the posture cards in the stat grid.
    // The Covered denominator is in the Covered split block (absent on a fresh profile).
    const knownBlock = readShown(htmlDoc.querySelector('[data-split="known"]')!);
    const coveredBlock = htmlDoc.querySelector('[data-split="covered"]');
    const htmlShown: Shown = { ...readShown(htmlDoc.querySelector('.stat-grid')!), mapped: knownBlock.mapped, total: knownBlock.total };
    if (coveredBlock) htmlShown.assessable = readShown(coveredBlock).assessable;

    return {
      ctem: readShown(card),
      validation: readShown(summary),
      reportBuilder: readShown(builderGrid),
      htmlReport: htmlShown,
      pdfReport: readShown(pdfDoc.querySelector('.summary-grid')!),
      statsBar: readShown(stats.nativeElement),
      words: {
        ctem: renderedWords(ctem.nativeElement),
        validation: renderedWords(validation.nativeElement),
        reportBuilder: renderedWords(builder.nativeElement),
        statsBar: renderedWords(stats.nativeElement),
        htmlReport: renderedWords(htmlDoc.body),
        pdfReport: renderedWords(pdfDoc.body),
      },
      htmlDoc,
      pdfDoc,
      statsEl: stats.nativeElement as HTMLElement,
      reportBuilderFixture: builder,
    };
  }

  const SURFACES = ['ctem', 'validation', 'reportBuilder', 'htmlReport', 'pdfReport', 'statsBar'] as const;

  // ── Fresh profile ─────────────────────────────────────────────────────────
  describe('fresh profile', () => {
    beforeEach(() => boot());

    it('every surface shows the same Known numbers, equal to mappedRollup, and no Covered or Proven words', () => {
      const known = TestBed.inject(EnrichmentService).mappedRollup(domain);
      const r = posture.rollup();
      expect(posture.ownerWords()).toBeFalse();
      expect([r.overall.mapped, r.overall.total]).toEqual([known.overall.mapped, known.overall.total]);
      const s = surfaces();
      for (const name of SURFACES) {
        expect(s[name]).withContext(name).toEqual({ mapped: known.overall.mapped, total: known.overall.total });
        expect(s.words[name]).withContext(`${name} renders an owner word on a fresh profile`).not.toMatch(OWNER_WORDS);
      }
    });

    it("actor-profile reads 'M techniques; no data of yours recorded' for every group, with no '%'", () => {
      const f = create(ActorProfilePanelComponent);
      const panel = f.componentInstance;
      for (const g of domain.groups) {
        panel.selectGroup(g);
        f.detectChanges();
        const el = f.nativeElement as HTMLElement;
        const m = TestBed.inject(DataService).getTechniquesForGroup(g.id).length;
        expect((el.querySelector('[data-testid="actor-posture-summary"]')?.textContent ?? '').trim())
          .withContext(g.attackId).toBe(`${m} techniques; no data of yours recorded`);
        expect(renderedWords(el)).withContext(g.attackId).not.toMatch(OWNER_WORDS);
        expect(el.textContent).withContext(g.attackId).not.toContain('%');
      }
    });
  });

  // ── Baseline seed: before / after against legacy-baseline.json (R9) ──────
  describe('M1047 + M1026 only (the legacy-baseline seed)', () => {
    beforeEach(() => boot());

    it('the legacy "implemented" parents become Covered = M1047 parents and partial = the rest of M1026 parents', () => {
      const s = picks();
      seed(s, false);
      const legacy = BASELINE.implementedEquality.seeded;
      const byBucket = (b: PostureBucket) => parents.filter(t => posture.stateFor(t).bucket === b).map(t => t.attackId).sort();
      const covered = byBucket('covered');
      const partial = byBucket('partial');
      expect(covered).toEqual(s.m1047Parents);
      expect(partial).toEqual(s.m1026Parents.filter(id => !s.m1047Parents.includes(id)));
      expect([...covered, ...partial].sort()).withContext('the same 15 parents, now split').toEqual(legacy.ids);
      const shown = surfaces();
      for (const name of SURFACES) {
        expect([shown[name].covered, shown[name].partial, shown[name].proven, shown[name].stale]).withContext(name)
          .toEqual([covered.length, partial.length, 0, 0]);
      }
      console.log(`[posture-equality] before ${JSON.stringify({
        statsBar: legacy.statsBar, reportImplemented: legacy.reportSplit, actorProfile: legacy.actorProfile,
        allMappedImplemented: legacy.allMappedImplemented, implementedPct: legacy.implementedPct,
      })}`);
      console.log(`[posture-equality] after ${JSON.stringify({
        covered: covered.length, partial: partial.length, proven: 0, stale: 0, coveredIds: covered, partialIds: partial,
      })}`);
    });
  });

  // ── Seeded profile ────────────────────────────────────────────────────────
  describe('seeded profile', () => {
    let s: Seed;
    let knownBefore: { mapped: number; total: number; pct: number };

    beforeEach(() => {
      boot();
      s = picks();
      const k = posture.rollup().overall;
      knownBefore = { mapped: k.mapped, total: k.total, pct: k.pct };
      seed(s, true);
    });

    it('the seed reaches every bucket the spec needs', () => {
      const state = (t: Technique) => posture.stateFor(t);
      expect(state(s.proof).bucket).toBe('proven');
      expect(state(s.failed).subStates).toContain('contradicted');
      expect(['known', 'none']).toContain(state(s.failed).bucket);
      expect(state(s.confirmed).bucket).toBe('covered');
      expect(state(s.notReproducible).excluded).toBeTrue();
      expect(posture.ownerWords()).toBeTrue();
    });

    it('[AC] identical Known, Covered, partial, Proven and stale on the card, the Validation summary, the report split and stats-bar', () => {
      const o = posture.rollup().overall;
      const expected: Shown = {
        mapped: o.mapped, total: o.total, assessable: o.assessable, covered: o.covered, partial: o.partial, proven: o.proven, stale: o.stale,
      };
      // The oracle of the seed: M1047's parents minus the proven and the contradicted one, plus the
      // confirmed M1026-only parent; partial is M1026's other parents.
      const only1026 = s.m1026Parents.filter(id => !s.m1047Parents.includes(id));
      expect(o.covered).toBe(s.m1047Parents.length - 2 + 1);
      expect(o.partial).toBe(only1026.length - 1);
      expect([o.proven, o.stale]).toEqual([1, 0]);
      const shown = surfaces();
      for (const name of SURFACES) expect(shown[name]).withContext(name).toEqual(expected);
      // The report split's own numbers (the HTML and PDF inputs) equal the rollup.
      const split = computeReportSplit(domain, posture.rollup(), TestBed.inject(ImplementationService).summarize()['implemented']);
      expect([split.known, split.total, split.covered, split.partial, split.proven, split.stale])
        .toEqual([o.mapped, o.total, o.covered, o.partial, o.proven, o.stale]);
      expect(split.implementedMitigations).toBe(2);
      console.log(`[posture-equality] seeded ${JSON.stringify({
        ...expected, assessable: o.assessable, notReproducible: o.notReproducible, contradicted: o.contradicted,
        proof: s.proof.attackId, failed: s.failed.attackId, confirmed: s.confirmed.attackId, notReproducibleRun: s.notReproducible.attackId,
      })}`);
    });

    it('[AC] R16 denominator: every Covered share divides by assessable (total - 1 here), overall and per tactic; Known keeps total', () => {
      const o = posture.rollup().overall;
      expect(o.assessable).withContext('the not-reproducible run excludes one parent').toBe(o.total - 1);
      expect(o.covered).toBeGreaterThan(0);
      const right = Math.round((o.covered / o.assessable) * 100);
      const shown = surfaces();
      for (const name of SURFACES) {
        expect([shown[name].total, shown[name].assessable]).withContext(`${name}: Known total, Covered denominator`).toEqual([o.total, o.assessable]);
      }
      const pctOf = (el: Element | null) => Number(el?.getAttribute('data-share-pct') ?? NaN);
      const split = computeReportSplit(domain, posture.rollup(), 2);
      expect([split.total, split.assessable, split.coveredPct]).toEqual([o.total, o.assessable, right]);
      expect(pctOf(shown.htmlDoc.querySelector('[data-split="covered"] [data-share-pct]'))).withContext('html donut').toBe(right);
      expect(shown.htmlDoc.documentElement.innerHTML).withContext('html donut arc')
        .toContain(`conic-gradient(#2563eb 0deg ${Math.round(right * 3.6)}deg`);
      expect(pctOf(shown.pdfDoc.querySelector('.summary-grid [data-share-pct]'))).withContext('pdf covered box').toBe(right);
      const builder = shown.reportBuilderFixture.nativeElement as HTMLElement;
      expect(pctOf(builder.querySelector('[data-testid="report-covered"] [data-share-pct]'))).withContext('report builder card').toBe(right);
      const bar = shown.statsEl.querySelector('.impl-bar') as HTMLElement;
      // The browser keeps 4 decimals of a width; the total-based width differs in the first decimal on this seed.
      const width = parseFloat((bar.querySelector('.impl-fill') as HTMLElement).style.width);
      expect(width).withContext('stats-bar width').toBeCloseTo((o.covered / o.assessable) * 100, 3);
      expect(Math.abs(width - (o.covered / o.total) * 100)).withContext('stats-bar width is not over total').toBeGreaterThan(0.1);
      expect(bar.getAttribute('title')).toContain(`${o.covered} of ${o.assessable} assessable parent techniques`);

      // Per tactic: the tactic rows carry assessable from tallyFor; one tactic holds the excluded parent.
      const rows = posture.rollup().byTactic;
      expect(rows.some(r => r.assessable === r.total - 1)).withContext('a tactic row loses the excluded parent').toBeTrue();
      for (const row of rows) {
        const want = row.assessable > 0 ? Math.round((row.covered / row.assessable) * 100) : 0;
        const htmlRow = shown.htmlDoc.querySelector(`.tactic-row[data-tactic="${row.shortname}"]`)!;
        const builderRow = builder.querySelector(`tr[data-tactic="${row.shortname}"]`)!;
        expect([readShown(htmlRow).assessable, pctOf(htmlRow.querySelector('[data-share-pct]'))]).withContext(`html ${row.shortname}`)
          .toEqual([row.assessable, want]);
        expect([readShown(builderRow).assessable, pctOf(builderRow.querySelector('[data-share-pct]'))]).withContext(`builder ${row.shortname}`)
          .toEqual([row.assessable, want]);
        const t = split.byTactic.find(x => x.shortname === row.shortname)!;
        expect([t.total, t.assessable, t.coveredPct]).withContext(`split ${row.shortname}`).toEqual([row.total, row.assessable, want]);
      }
    });

    it('actor-profile divides by the tally assessable for every group', () => {
      const f = create(ActorProfilePanelComponent);
      const panel = f.componentInstance;
      const data = TestBed.inject(DataService);
      let lowered = 0;
      for (const g of domain.groups) {
        panel.selectGroup(g);
        f.detectChanges();
        const techs = data.getTechniquesForGroup(g.id);
        const tally = posture.tallyFor(techs);
        if (tally.assessable < techs.length) lowered++;
        expect(panel.ringDenominator(panel.selectedProfile!)).withContext(g.attackId).toBe(tally.assessable);
      }
      const usesExcluded = domain.groups.some(g => data.getTechniquesForGroup(g.id).some(t => t.id === s.notReproducible.id));
      expect(lowered > 0).withContext('a group holding the excluded technique shows a lower denominator').toBe(usesExcluded);
    });

    it('per-tactic rows equal rollup().byTactic on the HTML report and the Report Builder', () => {
      const rows = posture.rollup().byTactic;
      const shown = surfaces();
      const builder = shown.reportBuilderFixture.nativeElement as HTMLElement;
      for (const row of rows) {
        const want = [row.covered, row.partial, row.proven, row.stale];
        const read = (root: ParentNode | null) => {
          const r = root ? readShown(root) : ({} as Shown);
          return [r.covered, r.partial, r.proven, r.stale];
        };
        expect(read(shown.htmlDoc.querySelector(`.tactic-row[data-tactic="${row.shortname}"]`))).withContext(`html ${row.shortname}`).toEqual(want);
        expect(read(builder.querySelector(`tr[data-tactic="${row.shortname}"]`))).withContext(`builder ${row.shortname}`).toEqual(want);
      }
      const split = computeReportSplit(domain, posture.rollup(), 2);
      expect(split.byTactic.map(t => [t.shortname, t.known, t.covered, t.partial, t.proven, t.stale]))
        .toEqual(rows.map(r => [r.shortname, r.mapped, r.covered, r.partial, r.proven, r.stale]));
    });

    it('R16: Known mapped and total equal mappedRollup; the not-reproducible run moves neither', () => {
      const known = TestBed.inject(EnrichmentService).mappedRollup(domain);
      const o = posture.rollup().overall;
      expect([o.mapped, o.total, o.pct]).toEqual([known.overall.mapped, known.overall.total, known.overall.pct]);
      expect([o.mapped, o.total, o.pct]).toEqual([knownBefore.mapped, knownBefore.total, knownBefore.pct]);
      expect(o.notReproducible).toBe(1);
      expect(o.assessable).toBe(o.total - 1);
      expect(posture.rollup().byTactic.map(r => [r.shortname, r.mapped, r.total]))
        .toEqual(known.byTactic.map(r => [r.shortname, r.mapped, r.total]));
    });

    it('population-scoped: for each fixture group, actor-profile covered and partial equal tallyFor(group techniques)', () => {
      const f = create(ActorProfilePanelComponent);
      const panel = f.componentInstance;
      const data = TestBed.inject(DataService);
      let nonZero = 0;
      for (const g of domain.groups) {
        panel.selectGroup(g);
        f.detectChanges();
        const el = f.nativeElement as HTMLElement;
        const techs = data.getTechniquesForGroup(g.id);
        const tally = posture.tallyFor(techs);
        const summary = (el.querySelector('[data-testid="actor-posture-summary"]')?.textContent ?? '').trim();
        expect(summary).withContext(g.attackId).toMatch(/^\d+ of \d+ techniques covered \(self-attested\), \d+ partial$/);
        expect(summary).withContext(g.attackId)
          .toBe(`${tally.covered} of ${tally.assessable} techniques covered (self-attested), ${tally.partial} partial`);
        const proven = (el.querySelector('[data-testid="actor-posture-proven"]')?.textContent ?? '').trim();
        expect(proven).withContext(g.attackId).toBe(`${postureBadge({ bucket: 'proven', qualifiers: [], proofScope: null, covered: [] })}: ${tally.proven} · ` +
          `${postureBadge({ bucket: 'stale', qualifiers: [], proofScope: null, covered: [] })}: ${tally.stale}`);
        expect(el.textContent).withContext(g.attackId).not.toContain('%');
        if (tally.covered + tally.partial > 0) nonZero++;
      }
      expect(nonZero).withContext('some group has a covered or partial technique').toBeGreaterThan(0);
    });

    it('per-technique: report badge, CSV cell and actor row dot equal the posture bucket for every fixture parent', async () => {
      const html = TestBed.inject(HtmlReportService);
      const builder = create(ReportPanelComponent);
      let blob = null as Blob | null;
      spyOn(URL, 'createObjectURL').and.callFake((b: Blob | MediaSource) => { blob = b as Blob; return 'blob:stub'; });
      spyOn(URL, 'revokeObjectURL').and.stub();
      spyOn(HTMLAnchorElement.prototype, 'click').and.stub();
      builder.componentInstance.exportCsv();
      const lines = (await blob!.text()).split('\n');
      const csvCell = (attackId: string): string => {
        const line = lines.find(l => l.startsWith(`"${attackId}",`));
        return /"([^"]*)"$/.exec(line ?? '')?.[1] ?? 'missing';
      };
      const actor = create(ActorProfilePanelComponent).componentInstance;

      for (const t of parents) {
        const state: PostureState = posture.stateFor(t);
        const badge = parse(html.techniqueBadge(t)).body.textContent;
        expect(badge).withContext(`badge ${t.attackId}`).toBe(postureBadge(state));
        expect(csvCell(t.attackId)).withContext(`CSV ${t.attackId}`).toBe(CSV_CELL[state.bucket]);
        expect(actor.getTechCoverage(t)).withContext(`dot ${t.attackId}`).toBe(ROW_DOT[state.bucket]);
      }

      // The most-mapped table renders the same badges.
      const doc = surfaces().htmlDoc;
      const tableRows = Array.from(doc.querySelectorAll('tr')).filter(tr => tr.querySelector('[data-bucket]'));
      expect(tableRows.length).toBeGreaterThan(0);
      for (const tr of tableRows) {
        const id = (tr.querySelector('td a')?.textContent ?? '').trim();
        expect((tr.querySelector('[data-bucket]')!.textContent ?? '').trim()).withContext(`table ${id}`).toBe(postureBadge(posture.stateFor(tech(id))));
      }
    });

    it("no technique of M1026 reads 'Implemented' unless confirmed or proven; the partial card equals rollup().overall.partial", () => {
      const html = TestBed.inject(HtmlReportService);
      for (const id of s.m1026Parents) {
        const t = tech(id);
        const state = posture.stateFor(t);
        const badge = parse(html.techniqueBadge(t)).body.textContent ?? '';
        expect(badge).withContext(id).not.toContain('Implemented');
        const full = state.covered.some(m => m.strength === 'full');
        if (!full && state.proof.length === 0) {
          expect(badge).withContext(id).toBe('Covered (self-attested, partial via M1026)');
        }
      }
      expect(posture.stateFor(s.confirmed).bucket).toBe('covered');
      const doc = surfaces().htmlDoc;
      expect(Number(doc.querySelector('.stat-grid [data-posture="partial"]')!.textContent)).toBe(posture.rollup().overall.partial);
      expect(doc.body.textContent).not.toContain('All mapped mitigations implemented');
      expect(doc.body.textContent).toContain('partial (broad mitigation, not confirmed per technique)');
    });
  });
});

// ── Seam grep (§4.2, R10) ────────────────────────────────────────────────────
/** The first `posture-rollup` regex: a mitigation-to-technique map or lookup. */
const POSTURE_ROLLUP_MAP = /mitigationsByTechnique|techniquesByMitigation|getTechniquesForMitigation|getMitigationsForTechnique/;
/** The second `posture-rollup` regex: the mitigation implementation store. */
const POSTURE_ROLLUP_STORE = /ImplementationService|implService|getStatusMap|ImplStatus/;

describe('posture-rollup seam grep (P2-07, §4.2): stats-bar, report-split and actor-profile-panel leave it', () => {
  const sources: Readonly<Record<string, string>> = {
    'src/app/components/stats-bar/stats-bar.component.ts': STATS_BAR_SRC as string,
    'src/app/models/report-split.ts': REPORT_SPLIT_SRC as string,
    'src/app/components/actor-profile-panel/actor-profile-panel.component.ts': ACTOR_PROFILE_SRC as string,
  };

  it('reads each source as text', () => {
    for (const [path, src] of Object.entries({ ...sources, 'src/app/services/html-report.service.ts': HTML_REPORT_SRC as string })) {
      expect(typeof src).withContext(path).toBe('string');
      expect(src).withContext(path).toContain('ATTACK-Navi - Copyright');
    }
  });

  for (const path of Object.keys(sources)) {
    it(`${path} does not match both posture-rollup regexes`, () => {
      const src = sources[path];
      expect(POSTURE_ROLLUP_MAP.test(src) && POSTURE_ROLLUP_STORE.test(src))
        .withContext(`${path} matches ${POSTURE_ROLLUP_MAP} and ${POSTURE_ROLLUP_STORE}`).toBeFalse();
    });
  }

  it('stats-bar keeps the relationship count (the first regex only); report-split and actor-profile match neither', () => {
    const stats = sources['src/app/components/stats-bar/stats-bar.component.ts'];
    expect([POSTURE_ROLLUP_MAP.test(stats), POSTURE_ROLLUP_STORE.test(stats)]).toEqual([true, false]);
    for (const path of ['src/app/models/report-split.ts', 'src/app/components/actor-profile-panel/actor-profile-panel.component.ts']) {
      expect([POSTURE_ROLLUP_MAP.test(sources[path]), POSTURE_ROLLUP_STORE.test(sources[path])]).withContext(path).toEqual([false, false]);
    }
  });

  it('is not vacuous: html-report.service still matches both (mitigation-level, listed until E9.1)', () => {
    const src = HTML_REPORT_SRC as string;
    expect(POSTURE_ROLLUP_MAP.test(src) && POSTURE_ROLLUP_STORE.test(src)).toBeTrue();
  });
});
