// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';
import { DataHealthComponent } from './data-health.component';
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

    // EpssService is injected but sources use of(true) inline - provide minimal mock
    const mockEpssService = {};

    // CveService exposes kevLoaded$ (not loaded$)
    const mockCveKevLoaded$ = new BehaviorSubject<boolean>(false);
    loadedSubjects['cveKev'] = mockCveKevLoaded$;
    const mockCveService = { kevLoaded$: mockCveKevLoaded$ };

    const mockDataService = {
      lastFetched$: of(null),
    };

    await TestBed.configureTestingModule({
      imports: [DataHealthComponent],
      providers: [
        provideHttpClient(),
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
    // EPSS uses of(true) inline so it loads immediately; all others start loading
    const loadingDots = fixture.nativeElement.querySelectorAll('.dot-loading');
    expect(loadingDots.length).toBe(23);
  });

  it('should transition dot to loaded state when service loads', () => {
    loadedSubjects['atomic'].next(true);
    fixture.detectChanges();
    // EPSS pre-loaded (of(true)) + atomic = 2 loaded
    const loadedDots = fixture.nativeElement.querySelectorAll('.dot-loaded');
    expect(loadedDots.length).toBe(2);
    const loadingDots = fixture.nativeElement.querySelectorAll('.dot-loading');
    expect(loadingDots.length).toBe(22);
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
