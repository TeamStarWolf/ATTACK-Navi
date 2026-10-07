// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap } from '@angular/router';
import { BehaviorSubject, Subject, of } from 'rxjs';

import { CveDossier } from '../../models/dossier';
import { CisaSsvcService } from '../../services/cisa-ssvc.service';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';
import { DossierService } from '../../services/dossier.service';
import { EpssService } from '../../services/epss.service';
import { F3FraudService } from '../../services/f3-fraud.service';
import { SsvcService } from '../../services/ssvc.service';
import { DossierPanelComponent } from './dossier-panel.component';

const A = 'CVE-2024-0001';
const B = 'CVE-2024-0002';

function liveDossier(id: string): CveDossier {
  return { cveId: id, source: 'live', warnings: [], techniques: [] } as unknown as CveDossier;
}

describe('DossierPanelComponent', () => {
  it('class is exported', () => {
    expect(DossierPanelComponent).toBeTruthy();
  });
});

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
