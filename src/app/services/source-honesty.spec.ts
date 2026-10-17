// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Source honesty (product plan 6.7, epic E1.3): every loader, forced offline, records
// its source as 'failed' with a reason and never reports it as loaded. Before E1.3
// about twenty loaders caught the error, substituted an empty value and marked
// themselves loaded, so a failed feed looked like a feed with nothing in it (#113 fixed
// KEV and NVD; this spec holds every other loader to the same rule).
//
// Each case starts the real service against HttpTestingController, then answers every
// request it makes (including retries, fallbacks and timeouts) with a network error.
import { Type } from '@angular/core';
import { TestBed, discardPeriodicTasks, fakeAsync, flush, flushMicrotasks, tick } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, TestRequest, provideHttpClientTesting } from '@angular/common/http/testing';
import { Observable } from 'rxjs';
import { SourceRegistryService } from './source-registry.service';
import { SOURCE_DEFINITIONS } from './source-inventory';
import { AnthropicSkillsService } from './anthropic-skills.service';
import { AtomicService } from './atomic.service';
import { AttackCveService } from './attack-cve.service';
import { CapecService } from './capec.service';
import { CARService } from './car.service';
import { ChangelogService } from './changelog.service';
import { CisaSsvcService } from './cisa-ssvc.service';
import { CisControlsService } from './cis-controls.service';
import { CloudControlsService } from './cloud-controls.service';
import { CriProfileService } from './cri-profile.service';
import { CsaCcmService } from './csa-ccm.service';
import { CveService } from './cve.service';
import { Cve2CapecService } from './cve2capec.service';
import { CweService } from './cwe.service';
import { D3fendService } from './d3fend.service';
import { AttackDomain, CACHED_LIVE_NOTE, DataService } from './data.service';
import { DossierService } from './dossier.service';
import { ElasticService } from './elastic.service';
import { EngageService } from './engage.service';
import { EpssService } from './epss.service';
import { EvtxSamplesService } from './evtx-samples.service';
import { ExploitdbService } from './exploitdb.service';
import { F3FraudService } from './f3-fraud.service';
import { IocFeedService } from './ioc-feed.service';
import { LibraryLayerService } from './library-layer.service';
import { LibraryService } from './library.service';
import { M365ControlsService } from './m365-controls.service';
import { M365DefenderService } from './m365-defender.service';
import { MispService } from './misp.service';
import { NistMappingService } from './nist-mapping.service';
import { NucleiService } from './nuclei.service';
import { NvdBulkService } from './nvd-bulk.service';
import { PayloadsService } from './payloads.service';
import { PocExploitService } from './poc-exploit.service';
import { SentinelRulesService } from './sentinel-rules.service';
import { SiemQueryService } from './siem-query.service';
import { SigmaService } from './sigma.service';
import { SplunkContentService } from './splunk-content.service';
import { SsvcService } from './ssvc.service';
import { ThreatHuntingService } from './threat-hunting.service';
import { ThreatHunterPlaybookService } from './threathunter-playbook.service';
import { VerisService } from './veris.service';

/** The current value of a hot boolean observable. */
function current(obs: Observable<boolean>): boolean | undefined {
  let value: boolean | undefined;
  obs.subscribe(v => (value = v)).unsubscribe();
  return value;
}

interface HonestyCase {
  /** The SourceRecord that must end up 'failed'. */
  id: string;
  service: Type<any>;
  /** Kick off the load (constructor-loaded services need nothing). */
  start?: (svc: any) => void;
  /** The service's own "loaded" flag, which must not be true after the failure. */
  loaded?: (svc: any) => boolean | undefined;
}

const dataCase = (id: string, mode: 'live' | 'bundled', domain: AttackDomain): HonestyCase => ({
  id,
  service: DataService,
  start: (svc: DataService) => {
    svc.setDataSourceMode(mode);
    svc.setAttackDomain(domain);
    svc.loadDomain();
  },
  loaded: (svc: DataService) => (mode === 'live' ? svc.freshness$.value === 'live' : svc.getCurrentDomain() !== null),
});

const CASES: HonestyCase[] = [
  dataCase('attack-enterprise', 'bundled', 'enterprise'),
  dataCase('attack-ics', 'bundled', 'ics'),
  dataCase('attack-mobile', 'bundled', 'mobile'),
  dataCase('attack-f3', 'bundled', 'f3'),
  dataCase('attack-live-enterprise', 'live', 'enterprise'),
  dataCase('attack-live-ics', 'live', 'ics'),
  dataCase('attack-live-mobile', 'live', 'mobile'),
  dataCase('attack-live-f3', 'live', 'f3'),
  { id: 'attack-f3', service: F3FraudService, start: s => s.ensureLoaded(), loaded: s => s.loaded },
  { id: 'attack-releases', service: ChangelogService, loaded: s => current(s.loaded$) },
  { id: 'cve-technique-map', service: NvdBulkService, loaded: s => current(s.loaded$) },
  { id: 'cve2capec-runtime', service: Cve2CapecService, loaded: s => current(s.loaded$) },
  { id: 'ctid-attack-to-cve', service: AttackCveService, loaded: s => current(s.loaded$) },
  { id: 'ctid-kev', service: AttackCveService, loaded: s => current(s.loaded$) },
  { id: 'cisa-kev', service: CveService, start: s => s.loadKev(), loaded: s => current(s.kevLoaded$) },
  // The live feed failing loads the dated snapshot in its place; offline, it fails too and
  // no catalogue is reported as loaded.
  { id: 'cisa-kev-snapshot', service: CveService, start: s => s.loadKev(), loaded: s => current(s.kevLoaded$) },
  { id: 'nvd', service: CveService, start: s => s.searchCves('CVE-2024-3400') },
  {
    id: 'nvd',
    service: CveService,
    start: s => {
      // Give the technique a CWE so the per-CWE NVD batch has something to request.
      spyOn(TestBed.inject(CapecService), 'getCapecForTechnique').and.returnValue([{ cweIds: ['78'] } as any]);
      s.fetchNvdCvesByAttackId('T1190').subscribe();
    },
  },
  { id: 'epss', service: EpssService, start: s => s.fetchScores(['CVE-2024-3400']).subscribe() },
  { id: 'cve-services', service: CisaSsvcService, start: s => s.fetchSsvc('CVE-2024-3400').subscribe() },
  { id: 'ctid-nist-800-53', service: NistMappingService, loaded: s => current(s.loaded$) },
  { id: 'ctid-cri-profile', service: CriProfileService, loaded: s => current(s.loaded$) },
  { id: 'ctid-csa-ccm', service: CsaCcmService, loaded: s => current(s.loaded$) },
  { id: 'ctid-veris', service: VerisService, loaded: s => current(s.loaded$) },
  { id: 'ctid-aws', service: CloudControlsService, loaded: s => current(s.loaded$) },
  { id: 'ctid-azure', service: CloudControlsService, loaded: s => current(s.loaded$) },
  { id: 'ctid-gcp', service: CloudControlsService, loaded: s => current(s.loaded$) },
  { id: 'ctid-m365', service: M365ControlsService, loaded: s => current(s.loaded$) },
  { id: 'sigmahq-coverage', service: SigmaService, loaded: s => current(s.loaded$) },
  { id: 'mdecrevoisier-sigma-tree', service: SigmaService, start: s => s.loadCommunityRules(), loaded: s => current(s.communityLoaded$) },
  { id: 'car-layer', service: CARService, loaded: s => current(s.loaded$) },
  { id: 'atomic-layer', service: AtomicService, loaded: s => current(s.loaded$) },
  { id: 'atomic-tests', service: AtomicService, start: s => s.fetchLiveTests('T1059.001').subscribe() },
  { id: 'capec', service: CapecService, loaded: s => current(s.loaded$) },
  { id: 'misp-galaxy', service: MispService, loaded: s => current(s.loaded$) },
  { id: 'engage', service: EngageService, loaded: s => current(s.loaded$) },
  { id: 'elastic-tree', service: ElasticService, loaded: s => current(s.loaded$) },
  { id: 'splunk-tree', service: SplunkContentService, loaded: s => current(s.loaded$) },
  { id: 'sentinel-attack-tree', service: SentinelRulesService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  { id: 'm365-hunting-queries', service: M365DefenderService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  { id: 'trickest-poc-tree', service: PocExploitService, loaded: s => current(s.loaded$) },
  { id: 'nuclei-tree', service: NucleiService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  { id: 'exploitdb', service: ExploitdbService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  { id: 'cyb3r-monk-hunting-tree', service: ThreatHuntingService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  { id: 'evtx-samples-tree', service: EvtxSamplesService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  // The curated folder map still serves the panel after this failure, so only the record is checked.
  { id: 'payloads-tree', service: PayloadsService, start: s => s.loadOnDemand() },
  { id: 'ipsum', service: IocFeedService, start: s => s.loadOnDemand(), loaded: s => current(s.loaded$) },
  { id: 'threathunter-playbook', service: ThreatHunterPlaybookService, loaded: s => current(s.loaded$) },
  { id: 'anthropic-skills-layer', service: AnthropicSkillsService, loaded: s => current(s.loaded$) },
  { id: 'cwe-catalog', service: CweService, loaded: s => current(s.loaded$) },
  { id: 'cwe-exploitation-anchor', service: CveService },
  { id: 'technique-queries', service: SiemQueryService },
  { id: 'ssvc-tables', service: SsvcService, loaded: s => current(s.loaded$) },
  { id: 'cve-dossiers', service: DossierService, loaded: s => s.indexLoaded },
  // D3fendService.loaded$ starts true for the compiled-in seed (its own record), so only
  // the ontology record is checked here.
  { id: 'd3fend-ontology', service: D3fendService },
  { id: 'd3fend-technique-api', service: D3fendService, start: s => s.getCountermeasures('T1059.001', true) },
  { id: 'library-index', service: LibraryService, loaded: s => current(s.loaded$) },
  { id: 'library-layers', service: LibraryLayerService, loaded: s => current(s.manifestLoaded$) },
  { id: 'library-layers', service: LibraryLayerService, start: s => s.setActive('web-application-attacks.json') },
];

/**
 * Sources with no loader to force offline. Each needs a reason; anything else in the
 * inventory must have a case above.
 */
const NO_LOADER: Record<string, string> = {
  'cis-controls': 'withdrawn upstream: no request is made (status archived-upstream, loaded$ false)',
  'cve-technique-counts': 'shipped but read by no code path',
  'lylat-mission-layers': 'shipped but read by no code path',
  'payloads-folder-map': 'compiled into the code',
  'offensive-tools': 'compiled into the code',
  'cwe-seed': 'compiled into the code',
  'd3fend-seed': 'compiled into the code',
  'car-seed': 'compiled into the code',
  'wazuh-rules': 'compiled into the code',
  'yara-templates': 'compiled into the code',
  'zeek-templates': 'compiled into the code',
  'suricata-templates': 'compiled into the code',
  'event-logging': 'compiled into the code',
  'ir-playbooks': 'compiled into the code',
};

/** Answer every request, including retries, fallbacks and timed-out ones, with a network error. */
function forceOffline(http: HttpTestingController, answer?: (req: TestRequest) => boolean): void {
  for (let round = 0; round < 40; round++) {
    flushMicrotasks();
    for (const req of http.match(() => true)) {
      if (req.cancelled) continue;
      if (answer?.(req)) continue;
      req.error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });
    }
    flushMicrotasks();
    tick(70_000); // past every retry backoff (1 s, 2 s, 4 s) and request timeout (10 s, 20 s)
  }
  flush();
  discardPeriodicTasks();
}

describe('source honesty: a failed loader never reports loaded (E1.3)', () => {
  let http: HttpTestingController;
  let registry: SourceRegistryService;

  beforeEach(() => {
    localStorage.removeItem('misp_config');
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpTestingController);
    registry = TestBed.inject(SourceRegistryService);
    // ThreatHuntingService uses fetch() rather than HttpClient.
    spyOn(window, 'fetch').and.callFake(() => Promise.reject(new TypeError('Failed to fetch (forced offline)')));
    // DataService checks IndexedDB before any request; keep the test off the real store.
    spyOn(DataService.prototype as any, 'loadFromIDB').and.returnValue(Promise.resolve(null));
    spyOn(DataService.prototype as any, 'saveToIDB').and.returnValue(Promise.resolve());
  });

  it('has a forced-failure case for every source with a loader', () => {
    const covered = new Set(CASES.map(c => c.id));
    const missing = SOURCE_DEFINITIONS.map(d => d.id).filter(id => !covered.has(id) && !(id in NO_LOADER));
    expect(missing).withContext('add a case to CASES or a reason to NO_LOADER').toEqual([]);
    const stale = Object.keys(NO_LOADER).filter(id => !SOURCE_DEFINITIONS.some(d => d.id === id));
    expect(stale).toEqual([]);
  });

  it('covers every live source', () => {
    const live = SOURCE_DEFINITIONS.filter(d => d.kind === 'live' && !(d.id in NO_LOADER)).map(d => d.id);
    expect(live.filter(id => !CASES.some(c => c.id === id))).toEqual([]);
    expect(live.length).toBeGreaterThan(40);
  });

  CASES.forEach((c, i) => {
    it(`${c.id} (${c.service.name}${c.start ? ', on demand' : ''}) records 'failed' with a reason [${i}]`, fakeAsync(() => {
      const svc = TestBed.inject(c.service);
      c.start?.(svc);
      forceOffline(http);

      const record = registry.get(c.id);
      expect(record.status).withContext(c.id).toBe('failed');
      expect(record.lastError).withContext(c.id).toBeTruthy();
      expect(record.lastLoadedAt).withContext(c.id).toBeNull();
      if (c.loaded) expect(c.loaded(svc)).withContext(`${c.id}: the service's own loaded flag`).not.toBeTrue();
    }));
  });

  // E1.4 (decision D2): a return visit in 'live' mode still paints the pinned bundle. The
  // start-of-session update check may answer from the IndexedDB copy of an earlier live
  // fetch; that copy is recorded as the live source's data and offered, never shown.
  it('records the live ATT&CK source as loaded from cache when the update check is answered from IndexedDB', fakeAsync(() => {
    const cachedDomain = { name: 'Enterprise ATT&CK', techniques: [{}, {}, {}], attackVersion: '20.0' };
    (DataService.prototype as any).loadFromIDB.and.returnValue(Promise.resolve(cachedDomain));
    const svc = TestBed.inject(DataService);
    svc.setDataSourceMode('live');
    svc.setAttackDomain('enterprise');
    svc.loadDomain();
    http.expectOne('assets/data/enterprise-attack.json')
      .flush({ objects: [{ type: 'x-mitre-collection', x_mitre_version: '19.2', modified: '2026-01-01' }] });
    flush();
    http.expectNone(() => true);
    const record = registry.get('attack-live-enterprise');
    expect(svc.freshness$.value).toBe('bundled');
    expect(svc.getCurrentDomain()?.attackVersion).toBe('19.2');
    expect(svc.update$.value).toEqual(jasmine.objectContaining({ status: 'available', pinnedVersion: '19.2', liveVersion: '20.0' }));
    expect(record.status).toBe('loaded');
    expect(record.rows).toBe(3);
    expect(record.version).toBe('20.0');
    expect(record.note).toBe(CACHED_LIVE_NOTE);
    expect(record.lastLoadedAt).not.toBeNull();
    discardPeriodicTasks();
  }));

  it('marks the never-requested withdrawn source (CIS) as archived-upstream, not loaded', fakeAsync(() => {
    const cis = TestBed.inject(CisControlsService);
    forceOffline(http);
    expect(registry.get('cis-controls').status).toBe('archived-upstream');
    expect(current(cis.loaded$)).toBeFalse();
  }));

  describe('services that cross-reference the CTID ATT&CK-to-CVE mapping', () => {
    const CSV_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv';
    const CSV = 'CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase\nCVE-2021-44228,T1190,,T1059,,\n';
    const ctidUp = (req: TestRequest) => {
      if (req.request.url !== CSV_URL) return false;
      req.flush(CSV);
      return true;
    };

    for (const [id, service] of [
      ['exploitdb', ExploitdbService],
      ['nuclei-tree', NucleiService],
      ['trickest-poc-tree', PocExploitService],
    ] as const) {
      it(`${id} records its own fetch failure once the mapping has loaded`, fakeAsync(() => {
        const svc = TestBed.inject(service as Type<any>);
        svc.loadOnDemand?.();
        forceOffline(http, ctidUp);
        expect(registry.get('ctid-attack-to-cve').status).toBe('archived-upstream');
        const record = registry.get(id);
        expect(record.status).toBe('failed');
        expect(record.lastError).toContain('network error');
        expect(current(svc.loaded$)).not.toBeTrue();
      }));

      it(`${id} is recorded as blocked, not pending forever, when the mapping fails`, fakeAsync(() => {
        const svc = TestBed.inject(service as Type<any>);
        svc.loadOnDemand?.();
        forceOffline(http);
        expect(registry.get(id).status).toBe('failed');
        expect(registry.get(id).lastError).toContain('blocked');
      }));
    }
  });
});
