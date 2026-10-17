// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Retry for the data-health view (product plan 6.4, epic E1.3): one entry per source
// with a loader, naming the service that owns it and how to run that loader again.
// The loaders record the outcome on the SourceRegistry themselves, so a Retry that
// fails again is shown as 'failed' with the new reason, never as loaded.
import { Injectable, Injector, Type, inject } from '@angular/core';
import { SourceRegistryService } from './source-registry.service';
import { SOURCE_DEFINITIONS } from './source-inventory';
import { AnthropicSkillsService } from './anthropic-skills.service';
import { AtomicService } from './atomic.service';
import { AttackCveService } from './attack-cve.service';
import { CapecService } from './capec.service';
import { CARService } from './car.service';
import { ChangelogService } from './changelog.service';
import { CisaSsvcService } from './cisa-ssvc.service';
import { CloudControlsService } from './cloud-controls.service';
import { CriProfileService } from './cri-profile.service';
import { CsaCcmService } from './csa-ccm.service';
import { CveService } from './cve.service';
import { Cve2CapecService } from './cve2capec.service';
import { CweService } from './cwe.service';
import { D3fendService } from './d3fend.service';
import { AttackDomain, DataService } from './data.service';
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

/**
 * Per-item sources (one request per CVE or technique) are retried with a fixed probe
 * item, so Retry answers "does the source answer now?" through the same service code
 * a view uses. CVE-2024-3400 is the journey-1 CVE; T1059.001 has Atomic and D3FEND data.
 */
export const RETRY_PROBE_CVE = 'CVE-2024-3400';
export const RETRY_PROBE_TECHNIQUE = 'T1059.001';

const DOMAIN_LABEL: Record<AttackDomain, string> = {
  enterprise: 'Enterprise',
  ics: 'ICS',
  mobile: 'Mobile',
  f3: 'F3',
};

export interface RetryEntry {
  /** The service that owns the loader. Resolved lazily, so an unused service is created only on Retry. */
  service: Type<any>;
  /** Run the loader again. */
  run: (svc: any, injector: Injector) => void;
  /** Why Retry cannot run right now, or null when it can. */
  blocked?: (injector: Injector) => string | null;
}

/**
 * An ATT&CK bundle: only the active domain's copy can be reloaded without changing what the
 * matrix shows. The live copy is fetched only by the update check (decision D2), so its
 * Retry / Load now runs "Check for ATT&CK update", which offers a newer release and never
 * applies it.
 */
function attackEntry(domain: AttackDomain, live: boolean): RetryEntry {
  return {
    service: DataService,
    run: (svc: DataService) => (live ? svc.checkForUpdate() : svc.loadDomain()),
    blocked: injector => {
      const data = injector.get(DataService);
      if (data.getCurrentAttackDomain() !== domain) {
        return `loads when the matrix is switched to ${DOMAIN_LABEL[domain]}`;
      }
      return null;
    },
  };
}

/** Every source with a loader, keyed by SourceRecord id. */
export const SOURCE_RETRY: Readonly<Record<string, RetryEntry>> = {
  'attack-enterprise': attackEntry('enterprise', false),
  'attack-ics': attackEntry('ics', false),
  'attack-mobile': attackEntry('mobile', false),
  // The F3 bundle also feeds the dossier overlap (F3FraudService) when F3 is not the active domain.
  'attack-f3': {
    service: F3FraudService,
    run: (svc: F3FraudService, injector) => {
      const data = injector.get(DataService);
      if (data.getCurrentAttackDomain() === 'f3') data.loadDomain();
      else svc.ensureLoaded();
    },
  },
  'attack-live-enterprise': attackEntry('enterprise', true),
  'attack-live-ics': attackEntry('ics', true),
  'attack-live-mobile': attackEntry('mobile', true),
  'attack-live-f3': attackEntry('f3', true),
  'attack-releases': { service: ChangelogService, run: (s: ChangelogService) => s.retry() },
  'cve-technique-map': { service: NvdBulkService, run: (s: NvdBulkService) => s.retry() },
  'cve2capec-runtime': { service: Cve2CapecService, run: (s: Cve2CapecService) => s.retry() },
  'ctid-attack-to-cve': { service: AttackCveService, run: (s: AttackCveService) => s.retry('ctid-attack-to-cve') },
  'ctid-kev': { service: AttackCveService, run: (s: AttackCveService) => s.retry('ctid-kev') },
  'cisa-kev': { service: CveService, run: (s: CveService) => s.loadKev() },
  'cisa-kev-snapshot': { service: CveService, run: (s: CveService) => s.loadKevSnapshot() },
  'epss': { service: EpssService, run: (s: EpssService) => s.checkAvailability().subscribe() },
  'nvd': { service: CveService, run: (s: CveService) => s.fetchCve(RETRY_PROBE_CVE).subscribe({ error: () => undefined }) },
  'cve-services': { service: CisaSsvcService, run: (s: CisaSsvcService) => s.fetchSsvc(RETRY_PROBE_CVE).subscribe() },
  'ctid-nist-800-53': { service: NistMappingService, run: (s: NistMappingService) => s.retry() },
  'ctid-cri-profile': { service: CriProfileService, run: (s: CriProfileService) => s.retry() },
  'ctid-csa-ccm': { service: CsaCcmService, run: (s: CsaCcmService) => s.retry() },
  'ctid-veris': { service: VerisService, run: (s: VerisService) => s.retry() },
  'ctid-aws': { service: CloudControlsService, run: (s: CloudControlsService) => s.retry('ctid-aws') },
  'ctid-azure': { service: CloudControlsService, run: (s: CloudControlsService) => s.retry('ctid-azure') },
  'ctid-gcp': { service: CloudControlsService, run: (s: CloudControlsService) => s.retry('ctid-gcp') },
  'ctid-m365': { service: M365ControlsService, run: (s: M365ControlsService) => s.retry() },
  'sigmahq-coverage': { service: SigmaService, run: (s: SigmaService) => s.loadLive() },
  'car-layer': { service: CARService, run: (s: CARService) => s.retry() },
  'atomic-layer': { service: AtomicService, run: (s: AtomicService) => s.retry() },
  'atomic-tests': { service: AtomicService, run: (s: AtomicService) => s.fetchLiveTests(RETRY_PROBE_TECHNIQUE).subscribe() },
  'capec': { service: CapecService, run: (s: CapecService) => s.retry() },
  'misp-galaxy': { service: MispService, run: (s: MispService) => s.retry() },
  'engage': { service: EngageService, run: (s: EngageService) => s.retry() },
  'elastic-tree': { service: ElasticService, run: (s: ElasticService) => s.retry() },
  'splunk-tree': { service: SplunkContentService, run: (s: SplunkContentService) => s.retry() },
  'sentinel-attack-tree': { service: SentinelRulesService, run: (s: SentinelRulesService) => s.retry() },
  'm365-hunting-queries': { service: M365DefenderService, run: (s: M365DefenderService) => s.retry() },
  'trickest-poc-tree': { service: PocExploitService, run: (s: PocExploitService) => s.retry() },
  'nuclei-tree': { service: NucleiService, run: (s: NucleiService) => s.retry() },
  'mdecrevoisier-sigma-tree': { service: SigmaService, run: (s: SigmaService) => s.loadCommunityRules() },
  'cyb3r-monk-hunting-tree': { service: ThreatHuntingService, run: (s: ThreatHuntingService) => s.retry() },
  'evtx-samples-tree': { service: EvtxSamplesService, run: (s: EvtxSamplesService) => s.retry() },
  'payloads-tree': { service: PayloadsService, run: (s: PayloadsService) => s.retry() },
  'exploitdb': { service: ExploitdbService, run: (s: ExploitdbService) => s.retry() },
  'ipsum': { service: IocFeedService, run: (s: IocFeedService) => s.retry() },
  'threathunter-playbook': { service: ThreatHunterPlaybookService, run: (s: ThreatHunterPlaybookService) => s.retry() },
  'anthropic-skills-layer': { service: AnthropicSkillsService, run: (s: AnthropicSkillsService) => s.retry() },
  'cwe-catalog': { service: CweService, run: (s: CweService) => s.retry() },
  'cwe-exploitation-anchor': { service: CveService, run: (s: CveService) => s.retryAnchor() },
  'technique-queries': { service: SiemQueryService, run: (s: SiemQueryService) => s.retry() },
  'ssvc-tables': { service: SsvcService, run: (s: SsvcService) => s.retry() },
  'cve-dossiers': { service: DossierService, run: (s: DossierService) => s.retry() },
  'd3fend-ontology': { service: D3fendService, run: (s: D3fendService) => s.retryOntologyIndex() },
  'd3fend-technique-api': { service: D3fendService, run: (s: D3fendService) => s.retryTechniqueApi(RETRY_PROBE_TECHNIQUE) },
  'library-index': { service: LibraryService, run: (s: LibraryService) => s.retry() },
  'library-layers': { service: LibraryLayerService, run: (s: LibraryLayerService) => s.retry() },
};

/** Sources with nothing to retry, each with the reason the data-health view shows. */
export const NO_RETRY_REASON: Readonly<Record<string, string>> = {
  'cis-controls': 'withdrawn upstream; nothing to fetch',
  'cve-technique-counts': 'shipped but read by no code path',
  'lylat-mission-layers': 'shipped but read by no code path',
  'payloads-folder-map': 'compiled into the app',
  'offensive-tools': 'compiled into the app',
  'cwe-seed': 'compiled into the app',
  'd3fend-seed': 'compiled into the app',
  'car-seed': 'compiled into the app',
  'wazuh-rules': 'compiled into the app',
  'yara-templates': 'compiled into the app',
  'zeek-templates': 'compiled into the app',
  'suricata-templates': 'compiled into the app',
  'event-logging': 'compiled into the app',
  'ir-playbooks': 'compiled into the app',
};

/**
 * Runs the Retry for one source. A source is retried only when it holds no data
 * (failed, empty, or never requested), so a Retry never re-indexes a loaded source
 * on top of itself.
 */
@Injectable({ providedIn: 'root' })
export class SourceRetryService {
  private readonly injector = inject(Injector);
  private readonly registry = inject(SourceRegistryService);

  /** True when the source has a loader Retry can run. */
  hasLoader(id: string): boolean {
    return id in SOURCE_RETRY;
  }

  /** Why Retry is not offered for `id` right now, or null when it is. */
  unavailableReason(id: string): string | null {
    const entry = SOURCE_RETRY[id];
    if (!entry) return NO_RETRY_REASON[id] ?? 'no loader';
    const record = this.registry.get(id);
    if (record.status === 'loading') return 'a request is in flight';
    if (this.registry.hasData(id)) return 'loaded; nothing to retry';
    return entry.blocked?.(this.injector) ?? null;
  }

  /** Run the loader for `id` again. Returns false when Retry is not available. */
  retry(id: string): boolean {
    if (this.unavailableReason(id) !== null) return false;
    const entry = SOURCE_RETRY[id];
    const svc = this.injector.get(entry.service);
    // A service that was never created this session starts its own load when it is
    // created; running the loader again would send a second request.
    if (this.registry.get(id).status === 'loading') return true;
    entry.run(svc, this.injector);
    return true;
  }
}

/** Every inventory id is either retryable or has a stated reason (checked by the spec). */
export function sourcesWithoutRetryDecision(): string[] {
  return SOURCE_DEFINITIONS.map(d => d.id).filter(id => !(id in SOURCE_RETRY) && !(id in NO_RETRY_REASON));
}
