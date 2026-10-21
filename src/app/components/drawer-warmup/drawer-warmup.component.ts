// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, inject, type ProviderToken } from '@angular/core';
import { AnnotationService } from '../../services/annotation.service';
import { AnthropicSkillsService } from '../../services/anthropic-skills.service';
import { AtomicService } from '../../services/atomic.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { AzureIdentityService } from '../../services/azure-identity.service';
import { BloodHoundService } from '../../services/bloodhound.service';
import { C2MappingService } from '../../services/c2-mapping.service';
import { CapecService } from '../../services/capec.service';
import { CARService } from '../../services/car.service';
import { CisControlsService } from '../../services/cis-controls.service';
import { CloudControlsService } from '../../services/cloud-controls.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { CsaCcmService } from '../../services/csa-ccm.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { CustomTechniqueService } from '../../services/custom-technique.service';
import { Cve2CapecService } from '../../services/cve2capec.service';
import { CweService } from '../../services/cwe.service';
import { D3fendService } from '../../services/d3fend.service';
import { DataService } from '../../services/data.service';
import { DocumentationService } from '../../services/documentation.service';
import { DrawerWidthService } from '../../services/drawer-width.service';
import { ElasticService } from '../../services/elastic.service';
import { EngageService } from '../../services/engage.service';
import { EpssService } from '../../services/epss.service';
import { EventLoggingService } from '../../services/event-logging.service';
import { EvtxSamplesService } from '../../services/evtx-samples.service';
import { ExploitdbService } from '../../services/exploitdb.service';
import { FilterService } from '../../services/filter.service';
import { ImplementationService } from '../../services/implementation.service';
import { IocFeedService } from '../../services/ioc-feed.service';
import { M365ControlsService } from '../../services/m365-controls.service';
import { M365DefenderService } from '../../services/m365-defender.service';
import { MispService } from '../../services/misp.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { NucleiService } from '../../services/nuclei.service';
import { OffensiveToolsService } from '../../services/offensive-tools.service';
import { OpenCtiService } from '../../services/opencti.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { PayloadsService } from '../../services/payloads.service';
import { PocExploitService } from '../../services/poc-exploit.service';
import { PostureService } from '../../services/posture.service';
import { RuleCoverageSnapshotService } from '../../services/rule-coverage-snapshot.service';
import { SiemQueryService } from '../../services/siem-query.service';
import { SigmaService } from '../../services/sigma.service';
import { TaggingService } from '../../services/tagging.service';
import { TechniqueMarksService } from '../../services/technique-marks.service';
import { ThreatHuntingService } from '../../services/threat-hunting.service';
import { ThreatHunterPlaybookService } from '../../services/threathunter-playbook.service';
import { UserLayerService } from '../../services/user-layer.service';
import { VerisService } from '../../services/veris.service';
import { WatchlistService } from '../../services/watchlist.service';
import { WazuhService } from '../../services/wazuh.service';
import { Router } from '@angular/router';

/**
 * Every root service the technique drawer (SidebarComponent) injects, in the
 * order its construction creates them: its constructor parameters first, in
 * declaration order (ChangeDetectorRef is the drawer's own, not a service),
 * then its inject() fields, in declaration order.
 */
export const DRAWER_BOOT_SERVICES: readonly ProviderToken<unknown>[] = [
  FilterService,
  PanelNavService,
  DataService,
  ImplementationService,
  DocumentationService,
  D3fendService,
  EngageService,
  CARService,
  AtomicService,
  TaggingService,
  AttackCveService,
  NistMappingService,
  CisControlsService,
  CloudControlsService,
  VerisService,
  CriProfileService,
  CapecService,
  CustomMitigationService,
  AnnotationService,
  WatchlistService,
  MispService,
  SigmaService,
  OpenCtiService,
  CweService,
  EpssService,
  ExploitdbService,
  NucleiService,
  CustomTechniqueService,
  M365DefenderService,
  SiemQueryService,
  PayloadsService,
  EventLoggingService,
  ElasticService,
  BloodHoundService,
  C2MappingService,
  IocFeedService,
  AzureIdentityService,
  OffensiveToolsService,
  WazuhService,
  ThreatHuntingService,
  CsaCcmService,
  M365ControlsService,
  Cve2CapecService,
  PocExploitService,
  AnthropicSkillsService,
  ThreatHunterPlaybookService,
  EvtxSamplesService,
  UserLayerService,
  Router,
  DrawerWidthService,
  PostureService,
  TechniqueMarksService,
  RuleCoverageSnapshotService,
];

/**
 * Keeps the boot order of the app's root services now that the technique drawer
 * (SidebarComponent) loads in a @defer block.
 *
 * At boot the drawer used to be created closed, in the app template's @if block,
 * and on the matrix its construction was the first creator of the services that
 * start 18 data requests: the CTID NIST 800-53, AWS, Azure, GCP, VERIS, CRI
 * Profile, CSA CCM and M365 mappings, the MISP galaxy, the SigmaHQ coverage
 * layer and the bundled rule-coverage snapshot (SigmaService), the CWE catalog,
 * the technique queries (SiemQueryService), the two CVE2CAPEC years, the
 * Anthropic skills and ThreatHunter Playbook layers, and the library-layer index
 * (reached through PostureService). Creating those services only when the
 * drawer's chunk arrives would move those requests. This component sits in the
 * drawer's old place, inside the same @if, and creates exactly the services the
 * drawer's construction created, in the same order, so every request starts at
 * the same point of the boot. The drawer's ngOnInit only subscribes to state
 * these services already hold, and its child components render only once a
 * technique is selected, so nothing else at boot depended on the drawer.
 *
 * It renders nothing.
 */
@Component({
  selector: 'app-drawer-warmup',
  standalone: true,
  template: '',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DrawerWarmupComponent {
  constructor() {
    for (const service of DRAWER_BOOT_SERVICES) inject(service);
  }
}
