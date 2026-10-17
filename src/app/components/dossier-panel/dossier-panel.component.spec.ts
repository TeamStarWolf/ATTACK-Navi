// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap, ParamMap } from '@angular/router';
import { BehaviorSubject, Subject, of } from 'rxjs';

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
  let cveService: jasmine.SpyObj<CveService> & { kevLoaded$: BehaviorSubject<boolean>; kevError$: BehaviorSubject<string | null> };
  /** The pending NVD fetchCve() for the CVE on screen, resolved by the test. */
  let nvdFetch: Subject<unknown>;
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
      jasmine.createSpyObj<CveService>('CveService', ['loadKev', 'getCachedCve', 'fetchCve']),
      { kevLoaded$: new BehaviorSubject<boolean>(false), kevError$: new BehaviorSubject<string | null>(null) },
    );
    cveService.getCachedCve.and.returnValue(null);
    nvdFetch = new Subject<unknown>();
    cveService.fetchCve.and.returnValue(nvdFetch as never);

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
      ssvc: { cveId: CVE, points: [], action: 'Act', actionTable: '', actionBlocked: null, timeline: 'P3D', timelineTable: '', timelineBlocked: null, warnings: [] },
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

    expect(cveService.fetchCve).toHaveBeenCalledOnceWith(CVE);
    expect(component.searching).toBeTrue();
    expect(component.notice).toContain('fetching it from NVD');
    expect(dossierService.load).toHaveBeenCalledTimes(1);

    nvdFetch.next({ id: CVE });
    nvdFetch.complete();

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
    expect(cveService.fetchCve).not.toHaveBeenCalled();
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

const A = 'CVE-2024-0001';
const B = 'CVE-2024-0002';

function liveDossier(id: string): CveDossier {
  return { cveId: id, source: 'live', warnings: [], techniques: [] } as unknown as CveDossier;
}

describe('DossierPanelComponent request handling', () => {
  let fixture: ComponentFixture<DossierPanelComponent>;
  let component: DossierPanelComponent;

  /** One pending load() per CVE id, resolved by the test in whatever order it likes. */
  let loads: Map<string, Subject<CveDossier>>;
  /** One pending fetchCve() per CVE id. */
  let fetches: Map<string, Subject<any>>;
  let cached: Map<string, any>;
  let fetchCve: jasmine.Spy;
  let load: jasmine.Spy;

  beforeEach(async () => {
    loads = new Map();
    fetches = new Map();
    cached = new Map();

    load = jasmine.createSpy('load').and.callFake((id: string) => {
      const s = new Subject<CveDossier>();
      loads.set(id, s);
      return s;
    });
    fetchCve = jasmine.createSpy('fetchCve').and.callFake((id: string) => {
      const s = new Subject<any>();
      fetches.set(id, s);
      return s;
    });

    await TestBed.configureTestingModule({
      imports: [DossierPanelComponent],
      providers: [
        {
          provide: DossierService,
          useValue: {
            load,
            reevaluate: (d: CveDossier) => d,
            recomputeF3: (d: CveDossier) => d,
            recomputeEnrichment: (d: CveDossier) => d,
          },
        },
        {
          provide: CveService,
          useValue: {
            loadKev: () => undefined,
            kevLoaded$: new BehaviorSubject(false),
            kevError$: new BehaviorSubject<string | null>(null),
            getCachedCve: (id: string) => cached.get(id) ?? null,
            fetchCve,
          },
        },
        { provide: EpssService, useValue: { getScore: () => null, fetchScores: () => of(null) } },
        { provide: SsvcService, useValue: { loaded$: of(false), timelineDays: () => 0 } },
        { provide: CisaSsvcService, useValue: { getSsvc: () => null, fetchSsvc: () => of(null) } },
        { provide: F3FraudService, useValue: { ensureLoaded: () => undefined, loaded$: of(false) } },
        { provide: DataService, useValue: { domain$: of(null) } },
        { provide: ActivatedRoute, useValue: { queryParamMap: of(convertToParamMap({})) } },
        { provide: Router, useValue: { navigate: () => Promise.resolve(true) } },
      ],
    })
      // The template is not under test here; the request state machine is.
      .overrideComponent(DossierPanelComponent, { set: { template: '', imports: [] } })
      .compileComponents();

    fixture = TestBed.createComponent(DossierPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  function submit(id: string): void {
    component.query = id;
    component.submit();
  }

  it('clears the searching latch when NVD fails, tells the reader, and fetches again for the next CVE', () => {
    submit(A);
    loads.get(A)!.next(liveDossier(A));
    expect(fetchCve).toHaveBeenCalledWith(A);
    expect(component.searching).toBe(true);

    fetches.get(A)!.error(new Error('Http failure response: 429 Too Many Requests'));
    expect(component.searching).toBe(false);
    expect(component.notice).toContain(`NVD lookup for ${A} failed`);
    expect(component.notice).toContain('429');

    // Before the fix `searching` stayed true here and B would never be fetched.
    submit(B);
    loads.get(B)!.next(liveDossier(B));
    expect(fetchCve).toHaveBeenCalledWith(B);
  });

  it('clears the latch on an NVD miss without calling it an error', () => {
    submit(A);
    loads.get(A)!.next(liveDossier(A));
    fetches.get(A)!.next(null);
    fetches.get(A)!.complete();

    expect(component.searching).toBe(false);
    expect(component.notice).toContain(`NVD has no record for ${A}`);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('rebuilds the dossier once the NVD record is in', () => {
    submit(A);
    loads.get(A)!.next(liveDossier(A));
    cached.set(A, { id: A });
    fetches.get(A)!.next({ id: A });
    fetches.get(A)!.complete();

    expect(component.searching).toBe(false);
    expect(component.notice).toBeNull();
    expect(load).toHaveBeenCalledTimes(2);
    loads.get(A)!.next({ ...liveDossier(A), description: 'rebuilt' });
    expect(component.dossier?.description).toBe('rebuilt');
  });

  it('ignores a dossier that arrives after a newer request and drops the stale subscription', () => {
    submit(A);
    const loadA = loads.get(A)!;
    submit(B);
    const loadB = loads.get(B)!;

    // A's request is cancelled the moment B is requested.
    expect(loadA.observed).toBe(false);

    loadB.next(liveDossier(B));
    expect(component.dossier?.cveId).toBe(B);

    // Even a late emission from A (had it not been cancelled) must not land on top of B.
    loadA.next(liveDossier(A));
    expect(component.dossier?.cveId).toBe(B);
    expect(component.loading).toBe(false);
  });

  it('drops an NVD result for a CVE that is no longer the one on screen', () => {
    submit(A);
    loads.get(A)!.next(liveDossier(A));
    const fetchA = fetches.get(A)!;
    submit(B);

    // B superseded A: A's fetch was cancelled and its outcome, if any, is ignored.
    expect(fetchA.observed).toBe(false);
    expect(component.searching).toBe(false);
    loads.get(B)!.next(liveDossier(B));
    expect(fetchCve).toHaveBeenCalledWith(B);
    expect(component.dossier?.cveId).toBe(B);
  });
});
