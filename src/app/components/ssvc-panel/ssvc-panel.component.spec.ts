// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';
import { KEV_LIVE, KEV_UNAVAILABLE, KevEntry, NvdCveItem, kevSnapshot } from '../../models/cve';
import { CveService } from '../../services/cve.service';
import { EpssService } from '../../services/epss.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { SsvcService } from '../../services/ssvc.service';
import { SsvcPanelComponent } from './ssvc-panel.component';

describe('SsvcPanelComponent', () => {
  it('class is exported', () => {
    expect(SsvcPanelComponent).toBeTruthy();
  });
});

describe('SsvcPanelComponent selection', () => {
  const KEV = {
    cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2',
    vulnerabilityName: '', dateAdded: '2021-12-10', shortDescription: '',
    requiredAction: '', dueDate: '2021-12-24',
    knownRansomwareCampaignUse: 'Known', notes: '',
  };

  function panel() {
    const c = Object.create(SsvcPanelComponent.prototype) as any;
    c.cveService = { getKevEntry: (id: string) => (id === KEV.cveID ? KEV : undefined) };
    c.ssvc = { evaluate: (cve: any) => ({ action: cve.isKev ? 'act' : 'track', points: [] }) };
    c.cdr = { markForCheck: () => undefined };
    c.tablesLoaded = true;
    c.env = { exposed: 'yes', mission: 'medium' };
    c.overrides = {};
    return c;
  }

  it('enriches a raw record from activeCve$ before evaluating it', () => {
    // A record parsed before KEV loaded keeps isKev:false forever; evaluating it raw
    // yields a weaker verdict that then sticks.
    const c = panel();
    c.select({ id: 'CVE-2021-44228', isKev: false, references: [] });
    expect(c.selected.isKev).toBe(true);
    expect(c.selected.kevKnownRansomware).toBe(true);
    expect(c.selectedResult.action).toBe('act');
  });

  it('clears overrides when the selection changes', () => {
    const c = panel();
    c.overrides = { automatable: 'no' };
    c.select({ id: 'CVE-2000-0001', isKev: false, references: [] });
    expect(c.overrides).toEqual({});
  });

  it('does not invent KEV membership for a CVE that is not listed', () => {
    const c = panel();
    c.select({ id: 'CVE-2000-0001', isKev: true, references: [] });
    expect(c.selected.isKev).toBe(false);
  });
});

describe('SsvcPanelComponent assess', () => {
  function panel(cached: Record<string, unknown> = {}) {
    const c = Object.create(SsvcPanelComponent.prototype) as any;
    const searched: string[] = [];
    c.searched = searched;
    c.cveService = {
      getCachedCve: (id: string) => (cached as any)[id] ?? null,
      getKevEntry: () => undefined,
      getAllCachedCves: () => Object.values(cached),
      searchCves: (q: string) => searched.push(q),
    };
    c.ssvc = {
      available: true,
      evaluate: () => ({ action: 'track', timeline: '60 days', points: [] }),
      timelineDays: () => 60,
      actionRank: () => 3,
    };
    c.epssService = { getScore: () => null, fetchScores: () => ({ subscribe: () => undefined }) };
    c.attackCve = { getMappingForCve: () => undefined };
    c.cdr = { markForCheck: () => undefined };
    c.tablesLoaded = true;
    c.env = { exposed: 'yes', mission: 'medium' };
    c.overrides = {};
    c.rows = [];
    c.subs = { add: () => undefined };
    return c;
  }

  const rec = (id: string) => ({ id, isKev: false, references: [], cvssVector: null });

  it('selects a CVE that is already cached, without waiting', () => {
    const c = panel({ 'CVE-2026-96769': rec('CVE-2026-96769') });
    c.query = 'CVE-2026-96769';
    c.search();
    expect(c.selected.id).toBe('CVE-2026-96769');
  });

  it('does not leave a previous CVE on screen while the new one loads', () => {
    // The reported symptom: Assess appeared to do nothing because the detail kept
    // showing the previously selected CVE.
    const c = panel({ 'CVE-2026-96770': rec('CVE-2026-96770') });
    c.select(rec('CVE-2026-96770'));
    c.query = 'CVE-2026-96769';
    c.search();
    expect(c.selected.id).toBe('CVE-2026-96770');   // not yet fetched
    // ...and once NVD answers, the requested CVE takes over.
    (c.cveService as any).getCachedCve = (id: string) =>
      id === 'CVE-2026-96769' ? rec('CVE-2026-96769') : null;
    (c.cveService as any).getAllCachedCves = () => [rec('CVE-2026-96769')];
    c.recompute();
    expect(c.selected.id).toBe('CVE-2026-96769');
  });

  it('issues the NVD search', () => {
    const c = panel();
    c.query = 'CVE-2026-96769';
    c.search();
    expect(c.searched).toEqual(['CVE-2026-96769']);
  });

  it('holds no pending selection for a keyword query', () => {
    const c = panel();
    c.query = 'apache struts';
    c.search();
    expect(c.pendingSelect).toBeNull();
  });
});

// Plan E1.3: SSVC with KEV missing shows 'decision blocked: exploitation unknown', never
// 'track'; with the live feed down, the bundled snapshot is used and its date is shown.
// Rendered with the real SsvcService and the real CERT/CC tables the app ships.
describe('SsvcPanelComponent KEV states (E1.3)', () => {
  let tables: object;
  let fixture: ComponentFixture<SsvcPanelComponent>;
  let kevLoaded$: BehaviorSubject<boolean>;
  let kevError$: BehaviorSubject<string | null>;
  let kevSnapshotDate$: BehaviorSubject<string | null>;
  let activeCve$: BehaviorSubject<NvdCveItem | null>;
  let kevMap: Map<string, KevEntry>;

  /** CVE-2024-3400 as NVD publishes it: network, no privileges, total impact. */
  const panOs = (): NvdCveItem => ({
    id: 'CVE-2024-3400', description: 'PAN-OS GlobalProtect command injection', cvssScore: 10, severity: 'CRITICAL',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwes: ['CWE-77'], cpes: [], published: '2024-04-12',
    lastModified: '', references: [], mappedAttackIds: [], isKev: false,
  });
  /** A CVE that the real tables put at 'track' whenever absence from KEV is read as 'not exploited'. */
  const quiet = (): NvdCveItem => ({
    ...panOs(), id: 'CVE-2024-0001', cvssScore: 4.2, severity: 'MEDIUM',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N',
  });

  const text = (sel: string): string => (fixture.nativeElement.querySelector(sel)?.textContent ?? '').replace(/\s+/g, ' ').trim();

  beforeAll(async () => {
    const response = await fetch('assets/data/ssvc-decision-tables.json');
    tables = await response.json();
  });

  beforeEach(() => {
    kevLoaded$ = new BehaviorSubject<boolean>(false);
    kevError$ = new BehaviorSubject<string | null>(null);
    kevSnapshotDate$ = new BehaviorSubject<string | null>(null);
    activeCve$ = new BehaviorSubject<NvdCveItem | null>(null);
    kevMap = new Map();
    const cached = new Map<string, NvdCveItem>();
    const cveService = {
      loadKev: jasmine.createSpy('loadKev'),
      kevLoaded$, kevError$, kevSnapshotDate$, activeCve$,
      nvdCache$: new BehaviorSubject(cached),
      searchResults$: of([]),
      loading$: of(false),
      error$: of(null),
      getKevEntry: (id: string) => kevMap.get(id),
      getAllCachedCves: () => [...cached.values()],
      getCachedCve: (id: string) => cached.get(id) ?? null,
      searchCves: () => undefined,
      get kevContext() {
        if (!kevLoaded$.value) return KEV_UNAVAILABLE;
        return kevSnapshotDate$.value ? kevSnapshot(kevSnapshotDate$.value) : KEV_LIVE;
      },
      cache: (c: NvdCveItem) => cached.set(c.id, c),
    };
    TestBed.configureTestingModule({
      imports: [SsvcPanelComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: CveService, useValue: cveService },
        { provide: EpssService, useValue: { getScore: () => null, fetchScores: () => of(new Map()) } },
        { provide: AttackCveService, useValue: { getMappingForCve: () => undefined } },
      ],
    });
    TestBed.inject(SsvcService); // loads its tables in the constructor
    TestBed.inject(HttpTestingController).expectOne('assets/data/ssvc-decision-tables.json').flush(tables);
    fixture = TestBed.createComponent(SsvcPanelComponent);
    fixture.detectChanges();
    (cveService as any).cache(panOs());
    (cveService as any).cache(quiet());
  });

  function show(cve: NvdCveItem): void {
    activeCve$.next(cve);
    fixture.componentInstance['recompute']();
    fixture.detectChanges();
  }

  it('control: with the live catalogue loaded, the quiet CVE resolves to track', () => {
    kevLoaded$.next(true);
    show(quiet());
    expect(text('[data-testid="ssvc-decision"] strong')).toBe('track');
  });

  it('with no KEV catalogue, shows "decision blocked: exploitation unknown" and never track', () => {
    kevError$.next('CISA KEV catalog could not be loaded: network error');
    show(quiet());

    expect(text('[data-testid="ssvc-decision"] strong')).toBe('decision blocked: exploitation unknown');
    expect(text('[data-testid="ssvc-decision"]')).toContain('Provisional: exploitation unknown');
    expect(text('[data-testid="ssvc-timeline"] strong')).toBe('blocked: KEV membership unknown');
    expect(text('[data-testid="kev-fact"]')).toBe('KEV unknown');
    expect(text('[data-testid="kev-unavailable-notice"]')).toContain('exploitation is unknown');
    // Every input is still shown, with Exploitation and In KEV as unknown.
    const rows = Array.from(fixture.nativeElement.querySelectorAll('table.points tbody tr')) as HTMLElement[];
    expect(rows.length).toBe(6);
    const exploitationRow = rows.find(r => r.textContent!.includes('Exploitation'))!;
    expect((exploitationRow.querySelector('select') as HTMLSelectElement).value).toBe('unknown');
    // No outcome anywhere on the panel reads track: not the verdict, not the worklist.
    const pills = Array.from(fixture.nativeElement.querySelectorAll('table.rows .pill')) as HTMLElement[];
    expect(pills.length).toBeGreaterThan(0);
    expect(pills.some(p => /^\s*track\*?\s*$/i.test(p.textContent!))).toBeFalse();
    expect(pills.filter(p => p.textContent!.includes('decision blocked: exploitation unknown')).length).toBe(2);
  });

  it('with the live feed down, decides from the bundled snapshot and says which snapshot', () => {
    kevError$.next('CISA KEV catalog could not be loaded: network error');
    kevMap.set('CVE-2024-3400', {
      cveID: 'CVE-2024-3400', vendorProject: 'Palo Alto Networks', product: 'PAN-OS', vulnerabilityName: '',
      dateAdded: '2024-04-12', dueDate: '2024-04-19', knownRansomwareCampaignUse: 'Known',
    });
    kevSnapshotDate$.next('2026-10-16');
    kevLoaded$.next(true);
    show(panOs());

    expect(text('[data-testid="kev-snapshot-notice"]')).toContain('Using the bundled CISA KEV snapshot of 2026-10-16');
    expect(text('[data-testid="kev-fact"]')).toBe('KEV yes, added 2024-04-12 (KEV snapshot of 2026-10-16)');
    expect(text('[data-testid="ssvc-decision"] strong')).toBe('act');
    expect(text('table.points')).toContain('bundled CISA KEV snapshot of 2026-10-16');
    expect(fixture.nativeElement.querySelector('[data-testid="kev-unavailable-notice"]')).toBeNull();
  });
});
