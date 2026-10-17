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
import { ImplStatus } from '../../services/implementation.service';
import { makeSplitDomain } from '../../testing/report-split-fixture';

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

// E1.1: the Report Builder shows a Theoretical / Implemented split. Reference
// mapping is labelled Theoretical; only owner-attested status is Implemented.
describe('ReportPanelComponent Theoretical / Implemented split (E1.1)', () => {
  let fixture: ComponentFixture<ReportPanelComponent>;
  let status$: BehaviorSubject<Map<string, ImplStatus>>;

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

  function render(statuses: Array<[string, ImplStatus]>): HTMLElement {
    localStorage.removeItem('mitre-nav-report-config-v1');
    status$ = new BehaviorSubject(new Map(statuses.map(([m, s]) => [`course-of-action--${m}`, s])));
    TestBed.configureTestingModule({
      imports: [ReportPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(reportDomain()) } },
        { provide: ImplementationService, useValue: {
            status$,
            summarize: () => ({ implemented: 0, 'in-progress': 0, planned: 0, 'not-started': 0 }),
        }},
        { provide: DocumentationService, useValue: { mitDocs$: new BehaviorSubject(new Map()) } },
        ReportConfigService,
      ],
    });
    fixture = TestBed.createComponent(ReportPanelComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  afterEach(() => localStorage.removeItem('mitre-nav-report-config-v1'));

  const text = (el: Element | null): string => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('labels the reference-derived count Theoretical and the owner-attested count Implemented (self-attested)', () => {
    const el = render([['M1', 'implemented']]);
    const theoretical = text(el.querySelector('[data-testid="report-theoretical"]'));
    const implemented = text(el.querySelector('[data-testid="report-implemented"]'));
    expect(theoretical).toContain('Theoretical: mitigation mapped');
    expect(theoretical).toContain('60%');
    expect(theoretical).toContain('3 / 5 techniques');
    expect(implemented).toContain('Implemented (self-attested)');
    expect(implemented).toContain('40%');
    expect(implemented).toContain('2 / 5 techniques');
  });

  it('shows 0% Implemented on a fresh profile while Theoretical stays at the reference value', () => {
    const el = render([]);
    expect(text(el.querySelector('[data-testid="report-theoretical"]'))).toContain('60%');
    expect(text(el.querySelector('[data-testid="report-implemented"]'))).toContain('0%');
    expect(text(el.querySelector('[data-testid="report-implemented"]'))).toContain('0 / 5 techniques');
  });

  it('never words or colours the Theoretical half as implemented, covered or protected', () => {
    const el = render([]);
    const card = el.querySelector('[data-testid="report-theoretical"]')!;
    expect(text(card)).not.toMatch(/implement|cover|protect|defend/i);
    expect(card.classList).not.toContain('green');
    expect(card.classList).not.toContain('implemented');
    // The retired 'Theoretical Coverage' / 'Implemented Coverage' cards are gone.
    expect(text(el)).not.toContain('Theoretical Coverage');
    expect(text(el)).not.toContain('Implemented Coverage');
    expect(text(el)).not.toContain('actively mitigated');
  });

  it('explains the split in the report header', () => {
    const note = text(render([]).querySelector('[data-testid="report-split-note"]'));
    expect(note).toContain("ATT&CK's reference mappings");
    expect(note).toContain('self-attested');
  });

  it('splits every tactic row into Theoretical and Implemented with no traffic-light colour', () => {
    const el = render([['M3', 'implemented']]);
    const table = el.querySelector('[data-testid="report-tactic-split"]')!;
    const headers = Array.from(table.querySelectorAll('th')).map(th => text(th));
    expect(headers).toEqual(['Tactic', 'Total', 'Theoretical (mapped)', 'Implemented (self-attested)', 'No mitigation mapped']);
    const rows = Array.from(table.querySelectorAll('tbody tr')).map(tr => Array.from(tr.querySelectorAll('td')).map(td => text(td)));
    expect(rows).toEqual([
      ['Execution', '3', '2 (67%)', '0 (0%)', 'T3'],
      ['Persistence', '2', '1 (50%)', '1 (50%)', 'T5'],
    ]);
    // Bars use the rung classes, not an inline green/amber/red background.
    for (const bar of Array.from(table.querySelectorAll<HTMLElement>('.mini-bar'))) {
      expect(bar.style.background).toBe('');
    }
    expect(table.querySelectorAll('.mini-bar--theoretical').length).toBe(2);
    expect(table.querySelectorAll('.mini-bar--implemented').length).toBe(2);
  });

  it('moves the Implemented half, and only it, when the owner marks a mitigation implemented', () => {
    const el = render([]);
    expect(text(el.querySelector('[data-testid="report-implemented"]'))).toContain('0%');
    status$.next(new Map([['course-of-action--M1', 'implemented']]));
    fixture.detectChanges();
    expect(text(el.querySelector('[data-testid="report-implemented"]'))).toContain('40%');
    expect(text(el.querySelector('[data-testid="report-theoretical"]'))).toContain('60%');
  });

  it('exports separate Theoretical and Implemented CSV columns', async () => {
    render([['M3', 'implemented']]);
    let blob = null as Blob | null;
    spyOn(URL, 'createObjectURL').and.callFake((b: Blob | MediaSource) => { blob = b as Blob; return 'blob:stub'; });
    spyOn(URL, 'revokeObjectURL').and.stub();
    spyOn(HTMLAnchorElement.prototype, 'click').and.stub();
    fixture.componentInstance.exportCsv();
    const lines = (await blob!.text()).split('\n');
    expect(lines[0]).toBe('Technique ID,Technique Name,Tactics,Platforms,Mitigations Mapped,Threat Groups,Theoretical: mitigation mapped,Implemented (self-attested)');
    const row = (id: string) => lines.find(l => l.startsWith(`"${id}",`))!.split(',').map(c => c.replace(/^"|"$/g, ''));
    expect(row('T1').slice(-2)).toEqual(['Yes', 'No']);
    expect(row('T3').slice(-2)).toEqual(['No', 'No']);
    expect(row('T4').slice(-2)).toEqual(['Yes', 'Yes']);
    expect(lines[0]).not.toMatch(/,Covered$/);
  });
});
