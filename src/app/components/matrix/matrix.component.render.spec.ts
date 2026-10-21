// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Behavioural specs for MatrixComponent against its REAL template, on the fixed
// fixture domain (src/app/testing/lens-harness.ts). The per-mode score maps are
// pinned separately by src/app/testing/lens-snapshots.spec.ts; this file pins
// what the matrix renders and how it reacts to the user.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { MatrixComponent } from './matrix.component';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { HEATMAP_MODES, LENS_NA_COLOR, unavailableLenses } from '../../models/heatmap-modes';
import { ValidationService } from '../../services/validation.service';
import {
  LENS_RUN_AGES, controlsProvider, lensPostureTodayProvider, lensRunTechniques, parseFixtureDomain, resetBrowserState,
  seedLensRuns, signal, signalStubProviders,
} from '../../testing/lens-harness';

describe('MatrixComponent (rendered, fixture domain)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<MatrixComponent>;
  let filter: FilterService;
  let host: HTMLElement;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        controlsProvider(domain),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const column = (tacticName: string): HTMLElement =>
    host.querySelector(`td.tactic-col[data-tactic="${tacticName}"]`) as HTMLElement;
  const cellIds = (el: ParentNode): string[] =>
    [...el.querySelectorAll('[data-tech-id]')].map(e => e.getAttribute('data-tech-id')!);

  it('renders one header per tactic, in matrix order', () => {
    const headers = [...host.querySelectorAll('th.tactic-header .tactic-name-text')].map(e => e.textContent!.trim());
    expect(headers).toEqual(domain.tacticColumns.map(c => c.tactic.name));
    expect(headers.length).toBe(15);
  });

  it('renders every parent technique of a tactic with its sub-techniques expanded', () => {
    for (const col of domain.tacticColumns) {
      const expected: string[] = [];
      for (const t of col.techniques) {
        expected.push(t.id);
        for (const s of t.subtechniques) expected.push(s.id);
      }
      expect(cellIds(column(col.tactic.name))).withContext(col.tactic.name).toEqual(expected);
    }
  });

  it('shows ATT&CK id and name on each cell', () => {
    const t = domain.techniques.find(x => x.attackId === 'T1003') as Technique;
    const cell = host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement;
    expect(cell.querySelector('.id')!.textContent!.trim()).toBe('T1003');
    expect(cell.querySelector('.name')!.textContent!.trim()).toBe(t.name);
    expect(cell.getAttribute('aria-label')).toBe(`T1003: ${t.name}`);
  });

  it('collapsing a parent removes its sub-technique cells', () => {
    const parent = domain.techniques.find(x => x.attackId === 'T1003') as Technique;
    const sub = parent.subtechniques[0];
    expect(host.querySelector(`[data-tech-id="${sub.id}"]`)).not.toBeNull();
    const btn = host.querySelector(`[data-tech-id="${parent.id}"]`)!.parentElement!.querySelector('.expand-btn') as HTMLButtonElement;
    btn.click();
    fixture.detectChanges();
    expect(host.querySelector(`[data-tech-id="${sub.id}"]`)).toBeNull();
  });

  it('clicking a cell selects that technique and marks it selected', () => {
    const t = domain.techniques.find(x => x.attackId === 'T1082') as Technique;
    let selected: Technique | null = null;
    filter.selectedTechnique$.subscribe(v => (selected = v));
    (host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement).click();
    fixture.detectChanges();
    expect(selected!.attackId).toBe('T1082');
    expect(host.querySelector(`[data-tech-id="${t.id}"] .cell`)!.classList).toContain('selected');
  });

  it('shows the no-results state for a search that matches nothing', () => {
    expect(host.querySelector('.no-results')).toBeNull();
    filter.setTechniqueSearch('zzzz-no-such-technique');
    fixture.detectChanges();
    expect(host.querySelector('.no-results')).not.toBeNull();
  });

  it('repaints cells when the heatmap lens changes', () => {
    // Pick a technique with Sigma rules and one without, from the stub data.
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    const withRules = parents.find(t => signal('sigma', t.attackId) > 0)!;
    const without = parents.find(t => signal('sigma', t.attackId) === 0)!;
    const bg = (t: Technique) => (host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement).style.backgroundColor;

    filter.setHeatmapMode('sigma');
    fixture.detectChanges();
    const sigmaWith = bg(withRules);
    const sigmaWithout = bg(without);
    expect(sigmaWith).not.toBe(sigmaWithout);

    filter.setHeatmapMode('coverage');
    fixture.detectChanges();
    expect([bg(withRules), bg(without)]).not.toEqual([sigmaWith, sigmaWithout]);
  });

  // E1.2 PR 2, no silent zeros: switching to ICS, a lens whose domains[] lacks
  // ics never renders an all-zero map; every cell shows 'n/a in this domain'.
  it('renders every lens that has no ICS data as n/a on every cell, never as its zero colour', () => {
    fixture.componentRef.setInput('attackDomain', 'ics');
    const disabled = unavailableLenses('ics');
    expect(disabled.length).toBe(23);
    const parent = domain.techniques.find(x => !x.isSubtechnique)!;
    for (const def of disabled) {
      filter.setHeatmapMode(def.value);
      fixture.detectChanges();
      expect(fixture.componentInstance.lensUnavailable).withContext(def.value).toBeTrue();
      const cells = Array.from(host.querySelectorAll<HTMLElement>('app-technique-cell .cell'));
      expect(cells.length).withContext(def.value).toBeGreaterThan(0);
      const notNa = cells.filter(c => !c.classList.contains('lens-na'));
      expect(notNa.length).withContext(`${def.value}: cells painted on the ramp`).toBe(0);
      expect(fixture.componentInstance.getMinimapCellColor(parent)).withContext(def.value).toBe(LENS_NA_COLOR);
      // No zero metric badge either (D3FEND would otherwise print a 0 on every cell).
      expect(host.querySelectorAll('.d3fend-badge, .atomic-badge, .cri-hm-badge').length).withContext(def.value).toBe(0);
    }
  });

  it('keeps painting a lens that has ICS data, and every lens on Enterprise except F3 origin', () => {
    fixture.componentRef.setInput('attackDomain', 'ics');
    filter.setHeatmapMode('frequency');
    fixture.detectChanges();
    expect(host.querySelectorAll('.cell.lens-na').length).toBe(0);

    fixture.componentRef.setInput('attackDomain', 'enterprise');
    for (const def of HEATMAP_MODES) {
      filter.setHeatmapMode(def.value);
      fixture.detectChanges();
      const naCells = host.querySelectorAll('.cell.lens-na').length;
      expect(naCells > 0).withContext(def.value).toBe(def.value === 'f3-origin');
    }
  });
});

// §7 Decay, Rendering (P2-13): on the Posture lens a stale cell's aria-label
// and tooltip name its proof age and the window it passed, "stale (N days;
// window W)". The harness pins POSTURE_TODAY and seeds one fresh and one
// stale own run (120 days old on the default 90-day own-run window).
describe('MatrixComponent (rendered, Posture lens, stale cell)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<MatrixComponent>;
  let host: HTMLElement;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        ...signalStubProviders(),
        controlsProvider(domain),
        lensPostureTodayProvider(),
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    seedLensRuns(TestBed.inject(ValidationService), domain);
    fixture = TestBed.createComponent(MatrixComponent);
    fixture.componentRef.setInput('domain', domain);
    fixture.detectChanges();
    TestBed.inject(FilterService).setHeatmapMode('posture');
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const cellOf = (t: Technique) => host.querySelector(`[data-tech-id="${t.id}"] .cell`) as HTMLElement;
  const tooltipOf = (t: Technique): string => {
    const cellHost = host.querySelector(`[data-tech-id="${t.id}"] app-technique-cell`) as HTMLElement;
    cellHost.dispatchEvent(new MouseEvent('mouseenter', { clientX: 10, clientY: 10 }));
    fixture.detectChanges();
    return cellHost.querySelector('.tt-posture')!.textContent!.trim();
  };

  it('names the proof age and the decay window on a stale cell, in the aria-label and the tooltip', () => {
    const { stale } = lensRunTechniques(domain);
    const words = `stale (${LENS_RUN_AGES.stale} days; window 90)`;
    expect(cellOf(stale).getAttribute('aria-label')).toBe(`${stale.attackId}: ${stale.name}, Proven (your run), ${words}`);
    expect(tooltipOf(stale)).toBe(`Proven (your run), ${words}`);
  });

  it('keeps the plain badge on a fresh proof', () => {
    const { fresh } = lensRunTechniques(domain);
    expect(cellOf(fresh).getAttribute('aria-label')).toBe(`${fresh.attackId}: ${fresh.name}, Proven (your run)`);
    expect(tooltipOf(fresh)).toBe('Proven (your run)');
  });
});
