// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { CveDossier } from '../models/dossier';
import { AtomicService } from './atomic.service';
import { AttackCveService } from './attack-cve.service';
import { CapecService } from './capec.service';
import { Cve2CapecService } from './cve2capec.service';
import { CveService } from './cve.service';
import { D3fendService } from './d3fend.service';
import { DataService } from './data.service';
import { DossierService } from './dossier.service';
import { EngageService } from './engage.service';
import { EpssService } from './epss.service';
import { NistMappingService } from './nist-mapping.service';
import { PocExploitService } from './poc-exploit.service';
import { SigmaService } from './sigma.service';
import { SsvcService } from './ssvc.service';

const KEV_ENTRY = {
  cveID: 'CVE-2021-44228',
  vendorProject: 'Apache',
  product: 'Log4j2',
  vulnerabilityName: 'Log4Shell',
  dateAdded: '2021-12-10',
  shortDescription: '',
  requiredAction: '',
  dueDate: '2021-12-24',
  knownRansomwareCampaignUse: 'Known',
  notes: '',
};

/** T1562 was retired in ATT&CK v19 in favour of T1685. */
const DOMAIN = {
  attackVersion: '19.2',
  techniques: [
    { id: 'attack-pattern--1', attackId: 'T1190', name: 'Exploit Public-Facing Application', tacticShortnames: ['initial-access'] },
    { id: 'attack-pattern--2', attackId: 'T1685', name: 'Disable or Modify Tools', tacticShortnames: ['defense-evasion'] },
  ],
  supersededBy: new Map([['T1562.001', 'T1685']]),
  retiredNames: new Map([['T1562.001', 'Disable or Modify Tools']]),
  mitigationsByTechnique: new Map(),
  detectionNotesByTechnique: new Map(),
};

function assetPayload(): Partial<CveDossier> {
  return {
    cveId: 'CVE-2021-44228',
    description: 'Log4Shell',
    cvssScore: 10,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    severity: 'CRITICAL',
    isKev: true,
    techniques: [
      { id: 'T1190', name: '', tier: 'exploitation', tactics: [] },
      { id: 'T1562.001', name: '', tier: 'weakness-class', tactics: [] },
    ],
    articles: [{ title: 'Inside Log4Shell', url: 'https://x.invalid', source: 'Cloudflare' }],
    warnings: [],
  };
}

describe('DossierService', () => {
  let service: DossierService;
  let httpMock: HttpTestingController;
  let cveStub: any;

  beforeEach(() => {
    cveStub = {
      getCachedCve: () => null,
      getKevEntry: (id: string) => (id === 'CVE-2021-44228' ? KEV_ENTRY : undefined),
      loadKev: () => undefined,
      kevLoaded$: { subscribe: () => ({ unsubscribe: () => undefined }) },
    };

    const stub = (impl: object) => ({ provide: null as any, useValue: impl });
    void stub;

    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [
        { provide: CveService, useValue: cveStub },
        {
          provide: SsvcService,
          useValue: {
            available: true,
            evaluate: (cve: any) => ({
              cveId: cve.id,
              points: [{ column: 'In KEV v1.0.0 (cisa)', label: 'In KEV', value: cve.isKev ? 'yes' : 'no', kind: 'derived', basis: '', options: [] }],
              action: cve.isKev ? 'act' : 'track',
              actionTable: '',
              timeline: cve.isKev ? '3 days & forensic investigation' : 'fix on system upgrade',
              timelineTable: '',
              warnings: [],
            }),
            timelineDays: () => 3,
          },
        },
        { provide: AttackCveService, useValue: { getMappingForCve: () => undefined } },
        { provide: Cve2CapecService, useValue: { getChainForCve: () => null } },
        { provide: CapecService, useValue: { getCapecForCwe: () => [], getCapecForTechnique: () => [] } },
        { provide: D3fendService, useValue: { getCountermeasures: () => [] } },
        { provide: EngageService, useValue: { getActivities: () => [] } },
        { provide: NistMappingService, useValue: { getControlsForTechnique: () => [] } },
        { provide: DataService, useValue: { getCurrentDomain: () => DOMAIN } },
        { provide: EpssService, useValue: { getScore: () => null, fetchScores: () => ({ subscribe: () => undefined }) } },
        { provide: PocExploitService, useValue: { hasPoc: () => false, getPocUrl: () => '' } },
        { provide: SigmaService, useValue: { getRuleCount: () => 0 } },
        { provide: AtomicService, useValue: { getTestCount: () => 0 } },
      ],
    });

    service = TestBed.inject(DossierService);
    httpMock = TestBed.inject(HttpTestingController);
    // The constructor requests the asset index.
    httpMock.expectOne('assets/data/dossiers/index.json').flush({ cves: ['CVE-2021-44228'] });
  });

  afterEach(() => httpMock.verify());

  it('prefers a generated asset when one exists', () => {
    let result: CveDossier | undefined;
    service.load('CVE-2021-44228').subscribe(d => (result = d));
    httpMock.expectOne('assets/data/dossiers/CVE-2021-44228.json').flush(assetPayload());

    expect(result?.source).toBe('asset');
    expect(result?.articles.length).toBe(1);
  });

  it('falls back to composing live when there is no asset', () => {
    let result: CveDossier | undefined;
    service.load('CVE-2000-0001').subscribe(d => (result = d));
    httpMock
      .expectOne('assets/data/dossiers/CVE-2000-0001.json')
      .flush('not found', { status: 404, statusText: 'Not Found' });

    expect(result?.source).toBe('live');
    // No NVD record cached, so it says so rather than rendering an empty dossier.
    expect(result?.warnings.some(w => w.includes('not in the NVD cache'))).toBe(true);
  });

  it('translates retired technique ids forward and keeps the tier', () => {
    let result: CveDossier | undefined;
    service.load('CVE-2021-44228').subscribe(d => (result = d));
    httpMock.expectOne('assets/data/dossiers/CVE-2021-44228.json').flush(assetPayload());

    const translated = result!.techniques.find(t => t.supersedes === 'T1562.001');
    expect(translated?.id).toBe('T1685');
    expect(translated?.name).toBe('Disable or Modify Tools');
    expect(translated?.tier).toBe('weakness-class');
    expect(translated?.unresolved).toBeFalsy();
  });

  it('reads KEV membership live rather than trusting the asset', () => {
    let result: CveDossier | undefined;
    service.load('CVE-2021-44228').subscribe(d => (result = d));
    httpMock
      .expectOne('assets/data/dossiers/CVE-2021-44228.json')
      .flush({ ...assetPayload(), isKev: false });

    expect(result?.isKev).toBe(true);
    expect(result?.kevRansomware).toBe(true);
  });

  it('recomputes the verdict with no NVD record cached', () => {
    // An asset opened by direct link has no cached CVE. Bailing out here left the
    // verdict computed before KEV loaded — materially weaker, not just missing a badge.
    const stale: CveDossier = {
      ...(assetPayload() as CveDossier),
      source: 'asset',
      generated: '',
      isKev: false,
      epss: null,
      epssPercentile: null,
      ssvc: null,
      cwes: [],
      capecs: [],
      mitigations: [],
      countermeasures: [],
      engage: [],
      controls: [],
      detection: [],
      exploits: { hasPoc: false, exploitDb: [], publicPocs: [], advisories: [], exploitTaggedRefs: [] },
      articles: [],
      warnings: [],
    };

    const updated = service.reevaluate(stale, { exposed: 'yes', mission: 'medium' });

    expect(updated.isKev).toBe(true);
    expect(updated.ssvc?.action).toBe('act');
    expect(updated.ssvc?.timeline).toBe('3 days & forensic investigation');
  });
});
