// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';
import { DataHealthComponent } from './data-health.component';
import { SourceRegistryService } from '../../services/source-registry.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CapecService } from '../../services/capec.service';
import { MispService } from '../../services/misp.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { CloudControlsService } from '../../services/cloud-controls.service';
import { VerisService } from '../../services/veris.service';
import { D3fendService } from '../../services/d3fend.service';
import { CARService } from '../../services/car.service';
import { ElasticService } from '../../services/elastic.service';
import { SplunkContentService } from '../../services/splunk-content.service';
import { ExploitdbService } from '../../services/exploitdb.service';
import { NucleiService } from '../../services/nuclei.service';
import { DataService } from '../../services/data.service';
import { EpssService } from '../../services/epss.service';
import { CveService } from '../../services/cve.service';
import { NvdBulkService } from '../../services/nvd-bulk.service';
import { Cve2CapecService } from '../../services/cve2capec.service';
import { PocExploitService } from '../../services/poc-exploit.service';
import { EvtxSamplesService } from '../../services/evtx-samples.service';
import { SentinelRulesService } from '../../services/sentinel-rules.service';
import { AnthropicSkillsService } from '../../services/anthropic-skills.service';
import { ThreatHunterPlaybookService } from '../../services/threathunter-playbook.service';

describe('DataHealthComponent', () => {
  let component: DataHealthComponent;
  let fixture: ComponentFixture<DataHealthComponent>;

  const loadedSubjects: Record<string, BehaviorSubject<boolean>> = {};
  let kevError$: BehaviorSubject<string | null>;
  let kevSnapshotDate$: BehaviorSubject<string | null>;
  let epssCheck$: BehaviorSubject<boolean>;

  // Services that expose loaded$ (used in the component's sources array)
  const loadedServiceNames = [
    'atomic', 'sigma', 'attackCve', 'capec', 'misp',
    'nist', 'cri', 'cloud', 'veris', 'd3fend',
    'car', 'elastic', 'splunk', 'exploitdb', 'nuclei',
    'nvdBulk', 'cve2capec', 'pocExploit', 'evtxSamples',
    'sentinelRules', 'anthropicSkills', 'threatHunterPlaybook',
  ];

  function makeMockService(): { loaded$: BehaviorSubject<boolean> } {
    const subj = new BehaviorSubject<boolean>(false);
    return { loaded$: subj };
  }

  beforeEach(async () => {
    const mocks: Record<string, any> = {};
    for (const name of loadedServiceNames) {
      const mock = makeMockService();
      loadedSubjects[name] = mock.loaded$;
      mocks[name] = mock;
    }

    // EPSS has a real availability check (E1.3) instead of a hard-coded of(true).
    epssCheck$ = new BehaviorSubject<boolean>(false);
    const mockEpssService = { checkAvailability: jasmine.createSpy('checkAvailability').and.returnValue(epssCheck$) };

    // CveService exposes kevLoaded$ (not loaded$) plus kevError$ for a failed fetch
    const mockCveKevLoaded$ = new BehaviorSubject<boolean>(false);
    loadedSubjects['cveKev'] = mockCveKevLoaded$;
    kevError$ = new BehaviorSubject<string | null>(null);
    kevSnapshotDate$ = new BehaviorSubject<string | null>(null);
    const mockCveService = { kevLoaded$: mockCveKevLoaded$, kevError$, kevSnapshotDate$ };

    const mockDataService = {
      lastFetched$: of(null),
    };

    await TestBed.configureTestingModule({
      imports: [DataHealthComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: AtomicService, useValue: mocks['atomic'] },
        { provide: SigmaService, useValue: mocks['sigma'] },
        { provide: AttackCveService, useValue: mocks['attackCve'] },
        { provide: CapecService, useValue: mocks['capec'] },
        { provide: MispService, useValue: mocks['misp'] },
        { provide: NistMappingService, useValue: mocks['nist'] },
        { provide: CriProfileService, useValue: mocks['cri'] },
        { provide: CloudControlsService, useValue: mocks['cloud'] },
        { provide: VerisService, useValue: mocks['veris'] },
        { provide: D3fendService, useValue: mocks['d3fend'] },
        { provide: CARService, useValue: mocks['car'] },
        { provide: ElasticService, useValue: mocks['elastic'] },
        { provide: SplunkContentService, useValue: mocks['splunk'] },
        { provide: ExploitdbService, useValue: mocks['exploitdb'] },
        { provide: NucleiService, useValue: mocks['nuclei'] },
        { provide: DataService, useValue: mockDataService },
        { provide: EpssService, useValue: mockEpssService },
        { provide: CveService, useValue: mockCveService },
        { provide: NvdBulkService, useValue: mocks['nvdBulk'] },
        { provide: Cve2CapecService, useValue: mocks['cve2capec'] },
        { provide: PocExploitService, useValue: mocks['pocExploit'] },
        { provide: EvtxSamplesService, useValue: mocks['evtxSamples'] },
        { provide: SentinelRulesService, useValue: mocks['sentinelRules'] },
        { provide: AnthropicSkillsService, useValue: mocks['anthropicSkills'] },
        { provide: ThreatHunterPlaybookService, useValue: mocks['threatHunterPlaybook'] },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DataHealthComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should show health dots for each service', () => {
    const dots = fixture.nativeElement.querySelectorAll('.health-dot');
    expect(dots.length).toBe(24);
  });

  it('should show dots in loading state initially', () => {
    // Every source starts loading, EPSS included: it is no longer hard-coded as up.
    const loadingDots = fixture.nativeElement.querySelectorAll('.dot-loading');
    expect(loadingDots.length).toBe(24);
  });

  it('should transition dot to loaded state when service loads', () => {
    loadedSubjects['atomic'].next(true);
    fixture.detectChanges();
    const loadedDots = fixture.nativeElement.querySelectorAll('.dot-loaded');
    expect(loadedDots.length).toBe(1);
    const loadingDots = fixture.nativeElement.querySelectorAll('.dot-loading');
    expect(loadingDots.length).toBe(23);
  });

  it('runs the EPSS availability check instead of reporting EPSS up unconditionally (E1.3)', () => {
    expect(TestBed.inject(EpssService).checkAvailability).toHaveBeenCalledTimes(1);
    const epssDot = () =>
      [...fixture.nativeElement.querySelectorAll('.health-dot')].find((d: Element) => d.getAttribute('title')!.startsWith('EPSS:')) as Element;
    expect(epssDot().classList).toContain('dot-loading');

    // The check failed: the registry turns the dot red with the reason.
    TestBed.inject(SourceRegistryService).fail('epss', 'no answer within 8 s from https://api.first.org/data/v1/epss');
    fixture.detectChanges();
    expect(epssDot().classList).toContain('dot-failed');
    expect(epssDot().getAttribute('title')).toContain('no answer within 8 s');
  });

  it('turns the EPSS dot loaded when a Retry succeeds after a failed check, as the registry says (E1.3)', () => {
    const registry = TestBed.inject(SourceRegistryService);
    const epssDot = () =>
      [...fixture.nativeElement.querySelectorAll('.health-dot')].find((d: Element) => d.getAttribute('title')!.startsWith('EPSS:')) as Element;

    // The availability check fails.
    epssCheck$.next(false);
    registry.fail('epss', 'network error reaching https://api.first.org/data/v1/epss');
    fixture.detectChanges();
    expect(epssDot().classList).toContain('dot-failed');

    // Retry: the check runs again and succeeds.
    registry.begin('epss');
    fixture.detectChanges();
    expect(epssDot().classList).toContain('dot-loading');
    registry.succeed('epss', null);
    fixture.detectChanges();
    expect(registry.get('epss').status).toBe('loaded');
    expect(epssDot().classList).toContain('dot-loaded');
    expect(epssDot().getAttribute('title')).toBe('EPSS: loaded');
  });

  it('shows EPSS loaded once the availability check answers', () => {
    epssCheck$.next(true);
    fixture.detectChanges();
    const loaded = [...fixture.nativeElement.querySelectorAll('.dot-loaded')] as Element[];
    expect(loaded.map(d => d.getAttribute('title'))).toEqual(['EPSS: loaded']);
  });

  it('marks CISA KEV failed when the fetch fails, and loaded once a retry succeeds', () => {
    kevError$.next('CISA KEV catalog could not be loaded: network error');
    fixture.detectChanges();
    const failed = fixture.nativeElement.querySelector('.dot-failed');
    expect(failed).toBeTruthy();
    expect(failed.getAttribute('title')).toContain('CISA KEV: failed');
    expect(failed.getAttribute('title')).toContain('network error');
    // A failed source is red, not pulsing yellow: a kevLoaded$ re-emission of false
    // (BehaviorSubject replay) must not demote it back to "loading".
    loadedSubjects['cveKev'].next(false);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.dot-failed').length).toBe(1);

    kevError$.next(null);
    loadedSubjects['cveKev'].next(true);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.dot-failed').length).toBe(0);
    expect(fixture.nativeElement.querySelectorAll('.dot-loaded').length).toBe(1);
  });

  it('keeps CISA KEV red while the bundled snapshot stands in, and names the snapshot date (E1.3)', () => {
    kevError$.next('CISA KEV catalog could not be loaded: network error');
    kevSnapshotDate$.next('2026-10-16');
    loadedSubjects['cveKev'].next(true);
    fixture.detectChanges();
    const failed = fixture.nativeElement.querySelector('.dot-failed');
    expect(failed).toBeTruthy();
    expect(failed.getAttribute('title')).toContain('CISA KEV: failed');
    expect(failed.getAttribute('title')).toContain('using the bundled KEV snapshot of 2026-10-16');
    expect(fixture.nativeElement.querySelectorAll('.dot-loaded').length).toBe(0);

    // The live feed arrives on Retry: the snapshot steps aside and the dot turns green.
    kevSnapshotDate$.next(null);
    kevError$.next(null);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.dot-failed').length).toBe(0);
    expect(fixture.nativeElement.querySelectorAll('.dot-loaded').length).toBe(1);
  });

  it('turns a dot red with the reason when its source records a failure, instead of pulsing "loading" (E1.3)', () => {
    const registry = TestBed.inject(SourceRegistryService);
    registry.fail('capec', 'HTTP 503 Service Unavailable');
    fixture.detectChanges();
    const failed = fixture.nativeElement.querySelector('.dot-failed');
    expect(failed).toBeTruthy();
    expect(failed.getAttribute('title')).toContain('CAPEC: failed');
    expect(failed.getAttribute('title')).toContain('HTTP 503');
    // The service's loaded$ replaying false does not demote it to "loading".
    loadedSubjects['capec'].next(false);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.dot-failed').length).toBe(1);
  });

  it('shows a source that answered with no rows as empty, not loaded and not loading', () => {
    TestBed.inject(SourceRegistryService).succeed('elastic-tree', 0);
    fixture.detectChanges();
    const empty = fixture.nativeElement.querySelector('.dot-empty');
    expect(empty).toBeTruthy();
    expect(empty.getAttribute('title')).toContain('Elastic Rules: empty');
  });

  it('keeps a multi-source entry out of the failed state while one of its sources still loads', () => {
    const registry = TestBed.inject(SourceRegistryService);
    registry.fail('ctid-aws', 'network error');
    registry.fail('ctid-azure', 'network error');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.dot-failed').length).toBe(0);
    registry.fail('ctid-gcp', 'network error');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.dot-failed').getAttribute('title')).toContain('Cloud Controls: failed');
  });

  it('should show refresh button', () => {
    const btn = fixture.nativeElement.querySelector('.refresh-btn');
    expect(btn).toBeTruthy();
  });

  it('should show last refreshed label after a service loads', () => {
    loadedSubjects['sigma'].next(true);
    fixture.detectChanges();
    const label = fixture.nativeElement.querySelector('.last-refreshed');
    expect(label).toBeTruthy();
    expect(label.textContent).toContain('Last refreshed');
  });
});
