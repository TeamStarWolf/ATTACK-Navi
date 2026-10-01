// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { CveDossier } from '../models/dossier';
import { AtomicService } from './atomic.service';
import { AttackCveService } from './attack-cve.service';
import { CapecService } from './capec.service';
import { CARService } from './car.service';
import { CisControlsService } from './cis-controls.service';
import { CriProfileService } from './cri-profile.service';
import { CsaCcmService } from './csa-ccm.service';
import { Cve2CapecService } from './cve2capec.service';
import { CveService } from './cve.service';
import { CweService } from './cwe.service';
import { D3fendService } from './d3fend.service';
import { DataService } from './data.service';
import { DossierService } from './dossier.service';
import { EngageService } from './engage.service';
import { EpssService } from './epss.service';
import { F3FraudService } from './f3-fraud.service';
import { M365ControlsService } from './m365-controls.service';
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

// DataService stub that answers the group/software/campaign lookups by STIX id — only
// attack-pattern--1 (T1190) carries actors, so the de-dupe across the two techniques is
// exercised too.
const dataStub = {
  getCurrentDomain: () => DOMAIN,
  getGroupsForTechnique: (id: string) =>
    id === 'attack-pattern--1' ? [{ attackId: 'G0016', name: 'APT29', url: 'https://attack.mitre.org/groups/G0016' }] : [],
  getSoftwareForTechnique: (id: string) =>
    id === 'attack-pattern--1' ? [{ attackId: 'S0002', name: 'Mimikatz', url: 'https://attack.mitre.org/software/S0002' }] : [],
  getCampaignsForTechnique: (id: string) =>
    id === 'attack-pattern--1' ? [{ attackId: 'C0001', name: 'Op Test', url: 'https://attack.mitre.org/campaigns/C0001' }] : [],
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
        {
          provide: CriProfileService,
          useValue: {
            getControlsForTechnique: (id: string) =>
              id === 'T1190' ? [{ id: 'PR.AC-1', description: 'Identities verified', functionLabel: 'Protect', url: 'https://cri' }] : [],
          },
        },
        {
          provide: CisControlsService,
          useValue: {
            getControlsForTechnique: (id: string) =>
              id === 'T1190' ? [{ id: 'CIS 4.1', description: 'Secure config', group: 'IG1', mappingType: 'mitigates' }] : [],
          },
        },
        {
          provide: CsaCcmService,
          useValue: {
            getControlsForTechnique: (id: string) =>
              id === 'T1190' ? [{ controlId: 'IVS-01', description: 'Network security', scoreCategory: 'protect', scoreValue: 'significant' }] : [],
          },
        },
        {
          provide: M365ControlsService,
          useValue: {
            getControlsForTechnique: (id: string) =>
              id === 'T1190' ? [{ controlId: 'EID-CA-E3', description: 'Conditional access', group: 'entra-id', scoreCategory: 'protect', scoreValue: 'significant', url: 'https://m365' }] : [],
          },
        },
        { provide: CweService, useValue: { getInfo: () => null } },
        {
          provide: CARService,
          useValue: { getAnalytics: (id: string) => (id === 'T1190' ? [{ id: 'CAR-2020-01', name: 'x', description: '', url: '', platforms: [], attackIds: ['T1190'] }] : []) },
        },
        {
          provide: F3FraudService,
          useValue: {
            ensureLoaded: () => undefined,
            loaded$: { subscribe: () => ({ unsubscribe: () => undefined }) },
            getOverlap: (id: string) => (id === 'T1190' ? { id: 'T1190', name: 'Exploit Public-Facing Application', url: 'https://ctid.mitre.org/fraud/techniques/T1190' } : null),
          },
        },
        { provide: DataService, useValue: dataStub },
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

  it('aggregates cross-framework enrichment and de-dupes across techniques', () => {
    let result: CveDossier | undefined;
    service.load('CVE-2021-44228').subscribe(d => (result = d));
    httpMock.expectOne('assets/data/dossiers/CVE-2021-44228.json').flush(assetPayload());

    // Control frameworks: NIST empty, the four CTID frameworks each contribute one.
    const frameworks = result!.controlFrameworks.map(f => f.framework);
    expect(frameworks).toContain('CRI Profile');
    expect(frameworks).toContain('CIS Controls');
    expect(frameworks).toContain('CSA CCM');
    expect(frameworks).toContain('Microsoft 365');
    expect(frameworks).not.toContain('NIST 800-53'); // no NIST hits → dropped, not shown empty

    // Threat actors are resolved via the STIX id of each technique.
    expect(result!.threatActors.groups.map(g => g.id)).toEqual(['G0016']);
    expect(result!.threatActors.software.map(s => s.id)).toEqual(['S0002']);
    expect(result!.threatActors.campaigns.map(c => c.id)).toEqual(['C0001']);

    // F3 overlap surfaces the one technique that carries a fraud interpretation.
    expect(result!.f3.techniques.map(t => t.id)).toEqual(['T1190']);

    // CISA SSVC is fetched by the panel, not the service, so it starts null.
    expect(result!.cisaSsvc).toBeNull();
  });

  it('recomputeEnrichment re-derives domain sections that were empty before the domain loaded', () => {
    // Simulates an asset opened by deep link before the ATT&CK bundle finished: the
    // domain-derived sections start empty and are filled once the domain is present.
    const base: CveDossier = {
      ...(assetPayload() as CveDossier),
      source: 'asset',
      generated: '',
      techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tier: 'exploitation', tactics: [] }],
      cwes: [],
      threatActors: { groups: [], software: [], campaigns: [] },
      controlFrameworks: [],
      f3: { techniques: [] },
    } as CveDossier;

    const updated = service.recomputeEnrichment(base);
    expect(updated.threatActors.groups.map(g => g.id)).toEqual(['G0016']);
    expect(updated.controlFrameworks.map(f => f.framework)).toContain('CRI Profile');
    expect(updated.f3.techniques.map(t => t.id)).toEqual(['T1190']);
  });

  it('recomputeF3 folds in the overlap without any refetch', () => {
    const base: CveDossier = {
      ...(assetPayload() as CveDossier),
      source: 'asset',
      generated: '',
      techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tier: 'exploitation', tactics: [] }],
      f3: { techniques: [] },
    } as CveDossier;

    const updated = service.recomputeF3(base);
    expect(updated.f3.techniques.map(t => t.id)).toEqual(['T1190']);
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
      cisaSsvc: null,
      cwes: [],
      capecs: [],
      mitigations: [],
      countermeasures: [],
      engage: [],
      controls: [],
      controlFrameworks: [],
      threatActors: { groups: [], software: [], campaigns: [] },
      f3: { techniques: [] },
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
