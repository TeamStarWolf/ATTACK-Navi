// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ReportPanelComponent } from './report-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { DocumentationService } from '../../services/documentation.service';
import { ReportConfigService } from '../../services/report-config.service';
import { Domain } from '../../models/domain';
import { makeSplitDomain } from '../../testing/report-split-fixture';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import type { PostureBucket } from '../../models/posture/posture.types';

describe('ReportPanelComponent', () => {
  let component: ReportPanelComponent;
  let fixture: ComponentFixture<ReportPanelComponent>;

  beforeEach(() => {
    localStorage.removeItem('mitre-nav-report-config-v1');

    TestBed.configureTestingModule({
      imports: [ReportPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: DocumentationService, useValue: {
            mitDocs$: new BehaviorSubject(new Map()),
            getMitDoc: () => ({ notes: '', owner: '', dueDate: '', controlRefs: '', evidenceUrl: '' }),
            getTechNote: () => '',
        }},
        ReportConfigService,
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(ReportPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    localStorage.removeItem('mitre-nav-report-config-v1');
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});

// E1.1 and P2-07: the Report Builder shows Known: mapped with the Theoretical
// sub-line from reference mapping, and Covered, partial and Proven from the
// posture rollup, so it cannot disagree with the posture card or the stats-bar.
// Covered and Proven words render only with owner data (§2.4).
describe('ReportPanelComponent split (E1.1, P2-07)', () => {
  let fixture: ComponentFixture<ReportPanelComponent>;
  let posture: PostureStub;

  function reportDomain(): Domain {
    const d = makeSplitDomain() as unknown as Record<string, unknown> & { techniques: Array<Record<string, unknown>> };
    for (const t of d.techniques) t['platforms'] = ['Windows'];
    return {
      ...d,
      mitigations: ['M1', 'M2', 'M3'].map(m => ({ id: `course-of-action--${m}`, attackId: m, name: `Mitigation ${m}` })),
      techniquesByMitigation: new Map(),
      groups: [],
      campaigns: [],
      groupsByTechnique: new Map(),
    } as unknown as Domain;
  }

  function render(buckets: Record<string, PostureBucket>, implemented = 0, telemetry: readonly string[] = []): HTMLElement {
    localStorage.removeItem('mitre-nav-report-config-v1');
    const domain = reportDomain();
    posture = makePostureStub(() => domain, buckets);
    posture.telemetry(telemetry);
    TestBed.configureTestingModule({
      imports: [ReportPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(domain) } },
        { provide: ImplementationService, useValue: {
            status$: new BehaviorSubject(new Map()),
            summarize: () => ({ implemented, 'in-progress': 0, planned: 0, 'not-started': 0 }),
        }},
        { provide: DocumentationService, useValue: { mitDocs$: new BehaviorSubject(new Map()) } },
        ReportConfigService,
        postureStubProvider(posture),
      ],
    });
    fixture = TestBed.createComponent(ReportPanelComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  afterEach(() => localStorage.removeItem('mitre-nav-report-config-v1'));

  const text = (el: Element | null): string => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
  const num = (el: Element, key: string): number => Number(text(el.querySelector(`[data-posture="${key}"]`)));

  it('labels the reference count Known: mapped with the Theoretical sub-line, and the owner count Covered (self-attested)', () => {
    const el = render({ T1: 'covered', T2: 'covered' }, 1);
    const known = text(el.querySelector('[data-testid="report-known"]'));
    expect(known).toContain('Known: mapped');
    expect(known).toContain('60%');
    expect(known).toContain('3 / 5 techniques');
    expect(text(el.querySelector('[data-testid="report-theoretical"]'))).toContain('Theoretical: mitigation mapped: 3 / 5 techniques (60%)');
    const covered = text(el.querySelector('[data-testid="report-covered"]'));
    expect(covered).toContain('Covered (self-attested)');
    expect(covered).toContain('2 of 5 assessable techniques (40%)');
    expect(num(el, 'covered')).toBe(2);
  });

  it('R16: the Covered card and the tactic mini-bars divide by assessable; Known keeps every technique', () => {
    const el = render({ T1: 'covered', T2: 'covered' }, 1);
    posture.exclude(['T3']);
    fixture.detectChanges();
    const covered = el.querySelector('[data-testid="report-covered"]')!;
    expect(text(covered)).toContain('2 of 4 assessable techniques (50%)');
    expect(num(covered, 'assessable')).toBe(4);
    expect(text(el.querySelector('[data-testid="report-known"]'))).toContain('3 / 5 techniques');
    const exec = el.querySelector('tr[data-tactic="execution"]')!;
    expect([num(exec, 'covered'), num(exec, 'assessable')]).toEqual([2, 2]);
    expect(exec.querySelector('[data-share-pct]')!.getAttribute('data-share-pct')).toBe('100');
    expect((exec.querySelector('.mini-bar--implemented') as HTMLElement).style.width).toBe('100%');
    expect(text(exec.querySelectorAll('td')[1])).withContext('the Total column keeps every parent').toBe('3');
  });

  it('shows Known only on a fresh profile, with no Covered or Proven words', () => {
    const el = render({});
    expect(text(el.querySelector('[data-testid="report-known"]'))).toContain('60%');
    expect(el.querySelector('[data-testid="report-covered"]')).toBeNull();
    expect(el.querySelector('[data-posture="covered"]')).toBeNull();
    expect(text(el)).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b/i);
    expect(text(el.querySelector('[data-testid="report-split-note"]'))).toContain('No data of yours recorded yet');
  });

  it('never words or colours the Known half as implemented, covered or protected', () => {
    const el = render({});
    const card = el.querySelector('[data-testid="report-known"]')!;
    expect(text(card)).not.toMatch(/implement|cover|protect|defend/i);
    expect(card.classList).not.toContain('green');
    expect(card.classList).not.toContain('implemented');
    // The retired 'Theoretical Coverage' / 'Implemented Coverage' cards are gone.
    expect(text(el)).not.toContain('Theoretical Coverage');
    expect(text(el)).not.toContain('Implemented Coverage');
    expect(text(el)).not.toContain('actively mitigated');
  });

  it('explains the split in the report header', () => {
    const note = text(render({ T1: 'covered' }).querySelector('[data-testid="report-split-note"]'));
    expect(note).toContain("ATT&CK's reference mappings");
    expect(note).toContain('self-attested');
    expect(note).toContain('partial');
  });

  // RP-F decision 36 (round 7, letter G): the Report Builder stated a breadth cause for
  // telemetry-only range partials; its note named only the broad mitigation.
  it('a report built from telemetry-only range rows names the telemetry cause and counts it; the note names both causes', () => {
    const el = render({ T1: 'partial', T2: 'partial' }, 0, ['T1', 'T2']);
    expect(Array.from(el.querySelectorAll('[data-testid="report-partial-cause"]')).map(e => text(e)))
      .toEqual(['partial (range telemetry, no alert credited): 2']);
    expect(text(el.querySelector('[data-testid="report-partial"]'))).not.toContain('broad mitigation');
    expect(text(el.querySelector('[data-testid="report-split-note"]')))
      .toContain('a broad mitigation not confirmed per technique, or range telemetry with no alert credited, counts as partial');
  });

  it('shows the partial card and the Proven count from the rollup', () => {
    const el = render({ T1: 'partial', T2: 'partial', T4: 'proven', T5: 'stale' }, 2);
    expect(text(el.querySelector('[data-testid="report-partial"]'))).toContain('partial, by cause');
    expect(Array.from(el.querySelectorAll('[data-testid="report-partial-cause"]')).map(e => text(e)))
      .toEqual(['partial (broad mitigation, not confirmed per technique): 2']);
    const overall = posture.rollup().overall;
    const summary = el.querySelector('.summary-grid')!;
    expect([num(summary, 'covered'), num(summary, 'partial'), num(summary, 'proven'), num(summary, 'stale')])
      .toEqual([overall.covered, overall.partial, overall.proven, overall.stale]);
    expect([overall.covered, overall.partial, overall.proven, overall.stale]).toEqual([0, 2, 1, 1]);
  });

  it('splits every tactic row into Theoretical and the posture buckets, with no traffic-light colour', () => {
    const el = render({ T4: 'covered' }, 1);
    const table = el.querySelector('[data-testid="report-tactic-split"]')!;
    const headers = Array.from(table.querySelectorAll('th')).map(th => text(th));
    expect(headers).toEqual(['Tactic', 'Total', 'Theoretical (mapped)', 'Covered (self-attested)', 'partial', 'Proven', 'No mitigation mapped']);
    const rows = Array.from(table.querySelectorAll('tbody tr')).map(tr => Array.from(tr.querySelectorAll('td')).map(td => text(td)));
    expect(rows).toEqual([
      ['Execution', '3', '2 (67%)', '0 of 3 (0%)', '0', '0 · stale 0', 'T3'],
      ['Persistence', '2', '1 (50%)', '1 of 2 (50%)', '0', '0 · stale 0', 'T5'],
    ]);
    // Bars use the rung classes, not an inline green/amber/red background.
    for (const bar of Array.from(table.querySelectorAll<HTMLElement>('.mini-bar'))) {
      expect(bar.style.background).toBe('');
    }
    expect(table.querySelectorAll('.mini-bar--theoretical').length).toBe(2);
    expect(table.querySelectorAll('.mini-bar--implemented').length).toBe(2);
  });

  it('hides the posture columns of the tactic table on a fresh profile', () => {
    const table = render({}).querySelector('[data-testid="report-tactic-split"]')!;
    expect(Array.from(table.querySelectorAll('th')).map(th => text(th))).toEqual(['Tactic', 'Total', 'Theoretical (mapped)', 'No mitigation mapped']);
  });

  it('moves the Covered count, and only it, when the posture states change', () => {
    const el = render({ T1: 'covered' });
    expect(num(el, 'covered')).toBe(1);
    posture.set({ T1: 'covered', T2: 'covered' });
    fixture.detectChanges();
    expect(num(el.querySelector('.summary-grid')!, 'covered')).toBe(2);
    expect(text(el.querySelector('[data-testid="report-known"]'))).toContain('60%');
  });

  it('fills the CSV Implemented column from the posture bucket; the header is unchanged', async () => {
    render({ T1: 'covered', T2: 'partial', T4: 'proven', T5: 'stale' }, 1);
    let blob = null as Blob | null;
    spyOn(URL, 'createObjectURL').and.callFake((b: Blob | MediaSource) => { blob = b as Blob; return 'blob:stub'; });
    spyOn(URL, 'revokeObjectURL').and.stub();
    spyOn(HTMLAnchorElement.prototype, 'click').and.stub();
    fixture.componentInstance.exportCsv();
    const lines = (await blob!.text()).split('\n');
    expect(lines[0]).toBe('Technique ID,Technique Name,Tactics,Platforms,Mitigations Mapped,Threat Groups,Theoretical: mitigation mapped,Implemented (self-attested)');
    const row = (id: string) => lines.find(l => l.startsWith(`"${id}",`))!.split(',').map(c => c.replace(/^"|"$/g, ''));
    expect(row('T1').slice(-2)).toEqual(['Yes', 'Yes']);
    expect(row('T2').slice(-2)).toEqual(['Yes', 'Partial']);
    expect(row('T3').slice(-2)).toEqual(['No', 'No']);
    expect(row('T4').slice(-2)).toEqual(['Yes', 'Yes']);
    expect(row('T5').slice(-2)).toEqual(['No', 'Yes']);
    expect(lines[0]).not.toMatch(/,Covered$/);
  });
});
