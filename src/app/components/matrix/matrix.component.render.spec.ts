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
import {
  controlsProvider, parseFixtureDomain, resetBrowserState, signal, signalStubProviders,
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
});
