// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// P2-10 [AC]: changing the shared threat profile moves every profile denominator in one
// step (design §3 P2-10, S8) — the wizard step-3 set, the gap-analysis total and the ctem
// posture-card "threat-relevant techniques: N" line all equal ThreatProfile.parentTechniqueIds.size.
// The all-groups dashboard/actor denominators (§10.4 item 15) do NOT move with the profile —
// asserted against the REAL DashboardPanelComponent and ActorProfilePanelComponent.
import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { HttpClient, provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject, of } from 'rxjs';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { AttackDomain, DataService } from '../services/data.service';
import { ThreatProfileService } from '../services/threat-profile.service';
import { GapAnalysisService } from '../services/gap-analysis.service';
import { SigmaService } from '../services/sigma.service';
import { ElasticService } from '../services/elastic.service';
import { SplunkContentService } from '../services/splunk-content.service';
import { M365DefenderService } from '../services/m365-defender.service';
import { AtomicService } from '../services/atomic.service';
import { CARService } from '../services/car.service';
import { AttackCveService } from '../services/attack-cve.service';
import { ExploitdbService } from '../services/exploitdb.service';
import { D3fendService } from '../services/d3fend.service';
import { CveService } from '../services/cve.service';
import { MispService } from '../services/misp.service';
import { OpenCtiService } from '../services/opencti.service';
import { EnrichmentService } from '../services/enrichment.service';
import { ImplementationService } from '../services/implementation.service';
import { TimelineService } from '../services/timeline.service';
import { PanelNavService } from '../services/panel-nav.service';
import { FilterService } from '../services/filter.service';
import { DashboardConfigService } from '../services/dashboard-config.service';
import { PostureCardComponent } from '../components/posture-card/posture-card.component';
import { AssessmentWizardComponent } from '../components/assessment-wizard/assessment-wizard.component';
import { DashboardPanelComponent } from '../components/dashboard-panel/dashboard-panel.component';
import { ActorProfilePanelComponent } from '../components/actor-profile-panel/actor-profile-panel.component';
import { THREAT_WEIGHT_PROVIDER } from '../models/posture/threat-weight';
import { POSTURE_TODAY } from '../models/posture/posture-today';
import { ThreatGroup } from '../models/group';
import { parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';
import { makePostureStub, postureStubProvider } from './posture-stub';

const TODAY = new Date('2026-10-01T00:00:00.000Z');
const cardLine = (f: { nativeElement: unknown }): number =>
  Number(((f.nativeElement as HTMLElement).querySelector('[data-posture="threat-relevant"]')?.textContent ?? '').trim());
const uniqueTechIds = (wiz: AssessmentWizardComponent): number =>
  new Set(wiz.tacticAssessments.flatMap(ta => ta.techniques.map(t => t.id))).size;

// ─── A. Profile denominators move together in one change-detection pass ──────────────
describe('threat-profile denominators move in one step (P2-10 [AC])', () => {
  let domain: Domain;
  let threatProfile: ThreatProfileService;
  let gap: GapAnalysisService;

  function load(d: Domain, id: AttackDomain): void {
    const ds = TestBed.inject(DataService) as unknown as {
      attackDomain: AttackDomain; currentDomain$: { next(v: AttackDomain): void }; domainSubject: { next(v: Domain | null): void };
    };
    ds.attackDomain = id;
    ds.currentDomain$.next(id);
    ds.domainSubject.next(d);
  }

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [PostureCardComponent, AssessmentWizardComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]),
        ...signalStubProviders(),
        { provide: POSTURE_TODAY, useValue: signal(TODAY) },
        { provide: THREAT_WEIGHT_PROVIDER, useExisting: ThreatProfileService },
        // Gap detection stubs (the lens-harness stubs answer different names); the gap
        // denominator is the profile, not detection counts, so 0/[] is fine.
        ...[SigmaService, ElasticService, SplunkContentService].map(t => ({ provide: t, useValue: { getRuleCount: () => 0 } })),
        { provide: M365DefenderService, useValue: { getQueriesForTechnique: () => [] } },
        { provide: AtomicService, useValue: { getTestCount: () => 0 } },
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AttackCveService, useValue: { getKevCvesForTechnique: () => [] } },
        { provide: ExploitdbService, useValue: { getExploitCount: () => 0 } },
      ],
    });
    load(domain, 'enterprise');
    threatProfile = TestBed.inject(ThreatProfileService);
    gap = TestBed.inject(GapAnalysisService);
  });

  afterEach(() => resetBrowserState());

  const gapTotal = () => gap.generateReport(domain, threatProfile.current).summary.totalTechniques;

  it('one setSource, one CD pass: the mounted card line and the wizard step-3 set equal parentTechniqueIds.size', () => {
    // Mount ONE card and ONE wizard BEFORE the change.
    const cardF = TestBed.createComponent(PostureCardComponent);
    cardF.componentRef.setInput('scope', 'threat-relevant');
    cardF.detectChanges();
    const wiz = TestBed.createComponent(AssessmentWizardComponent).componentInstance;
    (wiz as unknown as { domain: Domain }).domain = domain;

    const withTechs = domain.groups.filter(g => (domain.techniquesByGroup.get(g.id) ?? []).length > 0);
    expect(withTechs.length).withContext('fixture has >= 2 groups with techniques').toBeGreaterThanOrEqual(2);

    threatProfile.setSource({ kind: 'groups', ids: [withTechs[0].id, withTechs[1].id] });
    cardF.detectChanges();                                             // ONE pass reflects the new profile
    (wiz as unknown as { buildAssessment(): void }).buildAssessment(); // wizard rebuilds step 3

    const n = threatProfile.current.parentTechniqueIds.size;
    expect(n).toBeGreaterThan(0);
    expect(cardLine(cardF)).toBe(n);                 // rendered ctem line
    expect(uniqueTechIds(wiz)).toBe(n);              // the actual step-3 technique set (deduped)
    expect(wiz.totalTechniques).toBe(n);
    expect(gapTotal()).toBe(n);
  });

  it('Skip sets {kind:"all"}; the wizard/gap/card totals all equal the domain parent-technique count', () => {
    const wiz = TestBed.createComponent(AssessmentWizardComponent).componentInstance;
    (wiz as unknown as { domain: Domain }).domain = domain;

    wiz.setSkipGroups();   // → ThreatProfileService.setSource({kind:'all'})
    expect(threatProfile.current.source).toEqual({ kind: 'all' });

    const domainParents = domain.techniques.filter(t => !t.isSubtechnique).length;
    expect(threatProfile.current.parentTechniqueIds.size).toBe(domainParents);

    (wiz as unknown as { buildAssessment(): void }).buildAssessment();
    const cardF = TestBed.createComponent(PostureCardComponent);
    cardF.componentRef.setInput('scope', 'threat-relevant');
    cardF.detectChanges();

    expect(wiz.totalTechniques).toBe(domainParents);
    expect(uniqueTechIds(wiz)).toBe(domainParents);
    expect(gapTotal()).toBe(domainParents);
    expect(cardLine(cardF)).toBe(domainParents);
  });
});

// ─── B. The all-groups dashboard & actor denominators do NOT move (§10.4 item 15) ────
describe('all-groups denominators are profile-independent (P2-10 §10.4 item 15)', () => {
  // The dashboard reads groupsByTechnique/KEV/enrichment, never the token, so binding the
  // profile and changing it leaves criticalRiskCount/kevExposedGapCount unmoved. Fixture
  // mirrors dashboard-panel.component.spec (which this never edits).
  const tech = (attackId: string, tactic: string, mitigationCount = 0): Technique => ({
    id: `attack-pattern--${attackId}`, attackId, name: attackId, description: '', url: '',
    tacticShortnames: [tactic], isSubtechnique: attackId.includes('.'), parentId: null, subtechniques: [],
    mitigationCount, platforms: [], dataSources: [], detectionText: '', defenseBypassed: [],
    permissionsRequired: [], effectivePermissions: [], systemRequirements: [], impactType: [],
    remoteSupport: false, capecIds: [],
  });
  const T1003 = tech('T1003', 'credential-access', 3);
  const T1059 = tech('T1059', 'execution', 1);
  const T1190 = tech('T1190', 'initial-access');
  const T1566 = tech('T1566', 'initial-access');
  const ENRICHED = new Set(['T1003', 'T1059']);
  const col = (shortname: string, name: string, techniques: Technique[]) => ({
    tactic: { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order: 0 },
    techniques,
  });
  const g0 = { id: 'intrusion-set--g0', attackId: 'G0001', name: 'G0001', aliases: [] } as unknown as ThreatGroup;
  const DOMAIN = {
    name: 'Enterprise ATT&CK', attackVersion: '19.2',
    techniques: [T1003, T1059, T1190, T1566],
    mitigations: [{}, {}], groups: [g0],
    tacticColumns: [col('initial-access', 'Initial Access', [T1190, T1566]), col('execution', 'Execution', [T1059]), col('credential-access', 'Credential Access', [T1003])],
    groupsByTechnique: new Map([[T1190.id, [{}]], [T1003.id, [{}, {}]]]),
    mitigationsByTechnique: new Map([[T1003.id, [{}, {}, {}]], [T1059.id, [{}]]]),
    techniquesByGroup: new Map([[g0.id, [T1190, T1566]]]),
  } as unknown as Domain;

  let threatProfile: ThreatProfileService;
  let status$: BehaviorSubject<Map<string, string>>;

  beforeEach(() => {
    resetBrowserState();
    status$ = new BehaviorSubject(new Map<string, string>());
    const loaded = () => new BehaviorSubject<boolean>(false);
    const dataStub = {
      domain$: new BehaviorSubject(DOMAIN), currentDomain$: new BehaviorSubject<AttackDomain>('enterprise'),
      getCurrentDomain: () => DOMAIN, getCurrentAttackDomain: (): AttackDomain => 'enterprise',
      getTechniquesForGroup: (id: string) => (DOMAIN.techniquesByGroup.get(id) ?? []),
      getSoftwareForGroup: () => [], getCampaignsForGroup: () => [],
    };
    TestBed.configureTestingModule({
      imports: [DashboardPanelComponent, ActorProfilePanelComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]),
        { provide: DataService, useValue: dataStub },
        { provide: THREAT_WEIGHT_PROVIDER, useExisting: ThreatProfileService },
        postureStubProvider(makePostureStub(() => DOMAIN as never)),
        { provide: PanelNavService, useValue: { open: () => undefined } },
        { provide: FilterService, useValue: { toggleThreatGroup: () => undefined, selectTechnique: () => undefined } },
        { provide: EnrichmentService, useValue: {
            signals: (t: Technique) => ({ mitigation: ENRICHED.has(t.attackId), detection: false, atomic: false, d3fend: false, control: false, threatIntel: t.attackId === 'T1190', cve: t.attackId === 'T1190' }),
            referenceDefenseTotals: () => ({ total: 4, mapped: 2, mitigation: 2, detection: 1, control: 1, d3fend: 0, atomic: 0 }),
        } },
        { provide: ImplementationService, useValue: { status$, summarize: () => ({ implemented: 0, 'in-progress': 0, planned: 0, 'not-started': 0, untracked: 0 }) } },
        { provide: TimelineService, useValue: { getAll: () => [] } },
        { provide: AttackCveService, useValue: { loaded$: loaded(), getKevCvesForTechnique: (id: string) => (id === 'T1190' ? [{ cveId: 'CVE-2024-0001' }] : []), getCvesForTechnique: () => [] } },
        { provide: CARService, useValue: { loaded$: loaded(), getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { loaded$: loaded(), getTestCount: () => 0 } },
        { provide: D3fendService, useValue: { loaded$: loaded(), getCountermeasures: () => [] } },
        { provide: DashboardConfigService, useValue: { widgets$: new BehaviorSubject([{ id: 'gap-summary', label: 'Gaps', icon: '', visible: true, order: 0 }]) } },
        { provide: SigmaService, useValue: { loaded$: loaded(), getRuleCount: () => 0 } },
        { provide: ElasticService, useValue: { loaded$: loaded(), getRuleCount: () => 0 } },
        { provide: SplunkContentService, useValue: { loaded$: loaded(), getRuleCount: () => 0 } },
        { provide: CveService, useValue: { getKevEntry: () => undefined } },
        { provide: MispService, useValue: { loaded$: loaded(), total$: new BehaviorSubject(0) } },
        { provide: OpenCtiService, useValue: { connected$: new BehaviorSubject(false) } },
      ],
    });
    threatProfile = TestBed.inject(ThreatProfileService);
  });

  afterEach(() => resetBrowserState());

  it('dashboard criticalRiskCount and kevExposedGapCount stay fixed across a profile change', () => {
    const f = TestBed.createComponent(DashboardPanelComponent);
    f.detectChanges();
    const before = { crit: f.componentInstance.stats!.criticalRiskCount, kev: f.componentInstance.stats!.kevExposedGapCount };
    expect(before.crit).toBe(1);   // T1190: used by a group, undefended
    expect(before.kev).toBe(1);    // T1190: KEV-mapped, undefended

    threatProfile.setSource({ kind: 'groups', ids: [] });   // narrow the profile to nothing
    status$.next(new Map());                                 // force a stats rebuild
    f.detectChanges();
    expect(f.componentInstance.stats!.criticalRiskCount).toBe(before.crit);
    expect(f.componentInstance.stats!.kevExposedGapCount).toBe(before.kev);
  });

  it('actor-profile per-actor total stays fixed across a profile change', () => {
    const f = TestBed.createComponent(ActorProfilePanelComponent);
    f.detectChanges();
    f.componentInstance.selectGroup(g0);
    const before = f.componentInstance.selectedProfile!.techniques.length;
    expect(before).toBe(2);   // g0 uses T1190, T1566

    threatProfile.setSource({ kind: 'groups', ids: [] });
    f.componentInstance.selectGroup(g0);
    f.detectChanges();
    expect(f.componentInstance.selectedProfile!.techniques.length).toBe(before);
  });
});

// ─── C. Top-20 default: the service default and the rendered ctem line are 167 ───────
describe('Top-20 default threat-relevant count on bundled Enterprise 19.2 (P2-10)', () => {
  let domain: Domain;
  beforeAll(async () => {
    const bundle = await (await fetch('assets/data/enterprise-attack.json')).json();
    TestBed.configureTestingModule({ providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }] });
    domain = (TestBed.inject(DataService) as unknown as { parseBundle(b: unknown, n: string): Domain })
      .parseBundle(bundle, 'Enterprise ATT&CK');
    TestBed.resetTestingModule();
  }, 120_000);

  afterEach(() => resetBrowserState());

  it("the service's default profile and the rendered ctem threat-relevant line are both 167", () => {
    resetBrowserState();
    const dataStub = {
      domain$: new BehaviorSubject(domain), currentDomain$: new BehaviorSubject<AttackDomain>('enterprise'),
      getCurrentDomain: () => domain, getCurrentAttackDomain: (): AttackDomain => 'enterprise',
    };
    TestBed.configureTestingModule({
      imports: [PostureCardComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(),
        { provide: DataService, useValue: dataStub },
        { provide: THREAT_WEIGHT_PROVIDER, useExisting: ThreatProfileService },
        postureStubProvider(makePostureStub(() => domain as never)),
      ],
    });
    // The service, right after construction, defaults to Top-20 by prevalence.
    const threatProfile = TestBed.inject(ThreatProfileService);
    expect(threatProfile.current.source).toEqual({ kind: 'top-groups', n: 20 });
    expect(threatProfile.current.parentTechniqueIds.size).toBe(167);

    const f = TestBed.createComponent(PostureCardComponent);
    f.componentRef.setInput('scope', 'threat-relevant');
    f.detectChanges();
    expect(cardLine(f)).toBe(167);
  });
});
