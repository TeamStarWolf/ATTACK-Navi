// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap, ParamMap } from '@angular/router';
import { BehaviorSubject, of } from 'rxjs';

import { DossierPanelComponent } from './dossier-panel.component';
import { CveDossier } from '../../models/dossier';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';
import { DossierService } from '../../services/dossier.service';
import { EpssService } from '../../services/epss.service';
import { CisaSsvcService } from '../../services/cisa-ssvc.service';
import { F3FraudService } from '../../services/f3-fraud.service';
import { DEFAULT_ENVIRONMENT, SsvcService } from '../../services/ssvc.service';

const CVE = 'CVE-2021-44228';

function dossier(overrides: Partial<CveDossier> = {}): CveDossier {
  return {
    cveId: CVE,
    generated: '2026-01-01T00:00:00Z',
    source: 'asset',
    description: 'Log4Shell',
    cvssScore: 10,
    cvssVector: null,
    severity: 'CRITICAL',
    epss: null,
    epssPercentile: null,
    isKev: false,
    ssvc: null,
    cisaSsvc: null,
    cwes: [],
    capecs: [],
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tier: 'exploitation', tactics: ['initial-access'] },
      { id: 'T1685', name: 'Impair Defenses', tier: 'secondary-impact', tactics: ['defense-impairment'], supersedes: 'T1562' },
      { id: 'T1059', name: 'Command and Scripting Interpreter', tier: 'weakness-class', tactics: ['execution'] },
    ],
    mitigations: [],
    countermeasures: [
      { id: 'D3-NTA', name: 'Network Traffic Analysis', tactic: 'Detect', techniques: ['T1190'] },
      { id: 'D3-ACH', name: 'Application Configuration Hardening', tactic: 'Harden', techniques: ['T1190'] },
    ],
    engage: [],
    controls: [],
    controlFrameworks: [],
    threatActors: { groups: [], software: [], campaigns: [] },
    f3: { techniques: [] },
    detection: [],
    exploits: { hasPoc: false, exploitDb: [], publicPocs: [], advisories: [], exploitTaggedRefs: [] },
    articles: [],
    warnings: [],
    attackVersion: '19.2',
    ...overrides,
  };
}

describe('DossierPanelComponent', () => {
  let fixture: ComponentFixture<DossierPanelComponent>;
  let component: DossierPanelComponent;
  let el: HTMLElement;

  let queryParams: BehaviorSubject<ParamMap>;
  let dossierService: jasmine.SpyObj<DossierService>;
  let cveService: jasmine.SpyObj<CveService> & { kevLoaded$: BehaviorSubject<boolean>; nvdCache$: BehaviorSubject<Map<string, unknown>> };
  let epss: jasmine.SpyObj<EpssService>;
  let cisa: jasmine.SpyObj<CisaSsvcService>;
  let f3: { ensureLoaded: jasmine.Spy; loaded$: BehaviorSubject<boolean> };
  let ssvcLoaded$: BehaviorSubject<boolean>;
  let domain$: BehaviorSubject<unknown>;
  let router: jasmine.SpyObj<Router>;

  function setup(initialCve: string | null, loaded: CveDossier = dossier()): void {
    queryParams = new BehaviorSubject(convertToParamMap(initialCve ? { cve: initialCve } : {}));
    dossierService = jasmine.createSpyObj<DossierService>('DossierService', [
      'load', 'reevaluate', 'recomputeF3', 'recomputeEnrichment',
    ]);
    dossierService.load.and.returnValue(of(loaded));
    dossierService.reevaluate.and.callFake(d => d);
    dossierService.recomputeF3.and.callFake(d => ({ ...d, f3: { techniques: [{ id: 'T1190', name: 'Exploit', url: '' }] } }));
    dossierService.recomputeEnrichment.and.callFake(d => d);

    cveService = Object.assign(
      jasmine.createSpyObj<CveService>('CveService', ['loadKev', 'getCachedCve', 'searchCves']),
      { kevLoaded$: new BehaviorSubject<boolean>(false), nvdCache$: new BehaviorSubject(new Map<string, unknown>()) },
    );
    cveService.getCachedCve.and.returnValue(null);

    epss = jasmine.createSpyObj<EpssService>('EpssService', ['getScore', 'fetchScores']);
    epss.getScore.and.returnValue(null);
    epss.fetchScores.and.returnValue(of(new Map()));

    cisa = jasmine.createSpyObj<CisaSsvcService>('CisaSsvcService', ['getSsvc', 'fetchSsvc', 'tooltip']);
    cisa.getSsvc.and.returnValue(null);
    cisa.fetchSsvc.and.returnValue(of(null));

    f3 = { ensureLoaded: jasmine.createSpy('ensureLoaded'), loaded$: new BehaviorSubject<boolean>(false) };
    ssvcLoaded$ = new BehaviorSubject<boolean>(false);
    domain$ = new BehaviorSubject<unknown>(null);
    router = jasmine.createSpyObj<Router>('Router', ['navigate']);

    TestBed.configureTestingModule({
      imports: [DossierPanelComponent],
      providers: [
        { provide: DossierService, useValue: dossierService },
        { provide: CveService, useValue: cveService },
        { provide: EpssService, useValue: epss },
        { provide: SsvcService, useValue: { loaded$: ssvcLoaded$, timelineDays: () => 30 } },
        { provide: CisaSsvcService, useValue: cisa },
        { provide: F3FraudService, useValue: f3 },
        { provide: DataService, useValue: { domain$ } },
        { provide: ActivatedRoute, useValue: { queryParamMap: queryParams } },
        { provide: Router, useValue: router },
      ],
    });
    fixture = TestBed.createComponent(DossierPanelComponent);
    component = fixture.componentInstance;
    el = fixture.nativeElement;
    fixture.detectChanges();
  }

  const text = (selector: string) => (el.querySelector(selector)?.textContent ?? '').replace(/\s+/g, ' ').trim();
  /** The "KEV yes/no" fact (the `.kev` class is only added once the CVE is in KEV). */
  const kevFact = () =>
    Array.from(el.querySelectorAll('.facts .fact'))
      .map(n => (n.textContent ?? '').replace(/\s+/g, ' ').trim())
      .find(t => t.startsWith('KEV '));

  it('starts the KEV and F3 loads and opens the CVE named in ?cve= (case-insensitively)', () => {
    setup('cve-2021-44228');

    expect(cveService.loadKev).toHaveBeenCalled();
    expect(f3.ensureLoaded).toHaveBeenCalled();
    expect(dossierService.load).toHaveBeenCalledOnceWith(CVE, DEFAULT_ENVIRONMENT);
    expect(component.query).toBe(CVE);
    expect(component.loading).toBeFalse();
    expect(component.dossier?.cveId).toBe(CVE);
  });

  it('renders the technique tiers, the retired-id marker and the D3FEND groups', () => {
    setup(CVE);

    expect(text('.identity h3')).toContain(CVE);
    expect(kevFact()).toBe('KEV no');
    expect(el.querySelector('.fact.kev')).toBeNull();

    const tiers = Array.from(el.querySelectorAll('.tier .tier-name')).map(n => n.textContent?.trim());
    expect(tiers).toEqual(['Exploitation', 'Secondary impact', 'Weakness-class signals']);
    expect(text('.tier-exploitation .tech-id')).toBe('T1190');
    expect(el.querySelectorAll('.tech-chip.retired').length).toBe(1);
    expect(text('.hint')).toContain('2 technique(s) mapped to this CVE specifically');
    expect(text('.hint')).toContain('1 were mapped against an earlier ATT&CK release');

    // Countermeasures are grouped by D3FEND tactic in the canonical order.
    expect(component.countermeasuresByTactic.map(g => g.tactic)).toEqual(['Harden', 'Detect']);
    expect(component.retiredCount).toBe(1);
    expect(component.ctidCount).toBe(2);
  });

  it('re-evaluates the verdict when the KEV catalogue lands and shows the new outcome', () => {
    setup(CVE);
    dossierService.reevaluate.and.callFake(d => ({
      ...d,
      isKev: true,
      kevDueDate: '2026-02-01',
      ssvc: { cveId: CVE, points: [], action: 'Act', actionTable: '', timeline: 'P3D', timelineTable: '', warnings: [] },
    }));

    cveService.kevLoaded$.next(true);
    fixture.detectChanges();

    expect(dossierService.reevaluate).toHaveBeenCalledWith(jasmine.objectContaining({ cveId: CVE }), DEFAULT_ENVIRONMENT);
    expect(component.dossier?.isKev).toBeTrue();
    expect(kevFact()).toBe('KEV yes');
    expect(text('.fact.kev')).toBe('KEV yes');
    expect(el.querySelector('.facts')?.textContent).toContain('CISA due 2026-02-01');
    expect(el.querySelector('.verdict.action-act')).not.toBeNull();
    expect(component.actionClass('Act')).toBe('action-act');
    expect(component.timelineClass('P3D')).toBe('deadline-medium');
  });

  it('folds in an EPSS score that arrives after assembly', () => {
    setup(CVE);
    epss.getScore.and.returnValue({ cve: CVE, epss: 0.97, percentile: 0.99, date: '2026-01-01' } as never);

    ssvcLoaded$.next(true);
    fixture.detectChanges();

    expect(component.dossier?.epss).toBe(0.97);
    expect(component.dossier?.epssPercentile).toBe(0.99);
    expect(el.querySelector('.facts')?.textContent).toContain('EPSS 0.97');
  });

  it('folds the F3 overlap in when that bundle lands late', () => {
    setup(CVE);
    expect(dossierService.recomputeF3).not.toHaveBeenCalled();

    f3.loaded$.next(true);
    fixture.detectChanges();

    expect(dossierService.recomputeF3).toHaveBeenCalledTimes(1);
    expect(component.dossier?.f3.techniques.map(t => t.id)).toEqual(['T1190']);
  });

  it('re-derives domain sections once the ATT&CK bundle finishes parsing', () => {
    setup(CVE);
    expect(dossierService.recomputeEnrichment).not.toHaveBeenCalled();

    domain$.next({ name: 'Enterprise ATT&CK' });
    expect(dossierService.recomputeEnrichment).toHaveBeenCalledTimes(1);
  });

  it('fetches the NVD record once for a live dossier that is not cached, then rebuilds', () => {
    setup(CVE, dossier({ source: 'live' }));

    expect(cveService.searchCves).toHaveBeenCalledOnceWith(CVE);
    expect(component.searching).toBeTrue();
    expect(component.notice).toContain('fetching it from NVD');
    expect(dossierService.load).toHaveBeenCalledTimes(1);

    cveService.nvdCache$.next(new Map([[CVE, {}]]));

    expect(component.searching).toBeFalse();
    expect(component.notice).toBeNull();
    expect(dossierService.load).toHaveBeenCalledTimes(2);
  });

  it('does not refetch a live dossier whose NVD record is already cached', () => {
    setup(null);
    cveService.getCachedCve.and.returnValue({} as never);
    dossierService.load.and.returnValue(of(dossier({ source: 'live' })));

    queryParams.next(convertToParamMap({ cve: CVE }));

    expect(dossierService.load).toHaveBeenCalledTimes(1);
    expect(cveService.searchCves).not.toHaveBeenCalled();
  });

  it('rejects a malformed identifier without navigating or loading', () => {
    setup(null);
    component.query = 'log4shell';
    component.submit();

    expect(component.notice).toContain('Enter a CVE identifier');
    expect(router.navigate).not.toHaveBeenCalled();
    expect(dossierService.load).not.toHaveBeenCalled();
  });

  it('submit() writes the id to the URL and opens it', () => {
    setup(null);
    component.query = ' cve-2024-3094 ';
    component.submit();

    expect(router.navigate).toHaveBeenCalledWith([], jasmine.objectContaining({ queryParams: { cve: 'CVE-2024-3094' } }));
    expect(dossierService.load).toHaveBeenCalledOnceWith('CVE-2024-3094', DEFAULT_ENVIRONMENT);
  });

  it('shows an empty state when no technique is mapped', () => {
    setup(CVE, dossier({ techniques: [], countermeasures: [] }));
    expect(component.tierGroups).toEqual([]);
    expect(text('.block .empty')).toContain('No ATT&CK techniques are mapped');
  });
});
