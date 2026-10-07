// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';

import { DashboardPanelComponent } from './dashboard-panel.component';
import { Technique } from '../../models/technique';
import { DataService } from '../../services/data.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { ImplementationService } from '../../services/implementation.service';
import { TimelineService } from '../../services/timeline.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';
import { DashboardConfigService, DashboardWidget } from '../../services/dashboard-config.service';
import { SigmaService } from '../../services/sigma.service';
import { ElasticService } from '../../services/elastic.service';
import { SplunkContentService } from '../../services/splunk-content.service';
import { CveService } from '../../services/cve.service';
import { MispService } from '../../services/misp.service';
import { OpenCtiService } from '../../services/opencti.service';
import { EnrichmentService } from '../../services/enrichment.service';

function technique(attackId: string, name: string, tactic: string): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: 'desc', url: '',
    tacticShortnames: [tactic], isSubtechnique: attackId.includes('.'), parentId: null,
    subtechniques: [], mitigationCount: 0, platforms: [], dataSources: [], detectionText: '',
    defenseBypassed: [], permissionsRequired: [], effectivePermissions: [], systemRequirements: [],
    impactType: [], remoteSupport: false, capecIds: [],
  };
}

const T1003 = technique('T1003', 'OS Credential Dumping', 'credential-access');
const T1059 = technique('T1059', 'Command and Scripting Interpreter', 'execution');
const T1059_001 = technique('T1059.001', 'PowerShell', 'execution');
const T1190 = technique('T1190', 'Exploit Public-Facing Application', 'initial-access');
const T1566 = technique('T1566', 'Phishing', 'initial-access');
const ENRICHED = new Set(['T1003', 'T1059']);

const tacticCol = (shortname: string, name: string, techniques: Technique[]) => ({
  tactic: { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order: 0 },
  techniques,
});

const DOMAIN = {
  name: 'Enterprise ATT&CK',
  techniques: [T1003, T1059, T1059_001, T1190, T1566],
  mitigations: [{}, {}, {}, {}, {}, {}],
  groups: [{}, {}],
  tacticColumns: [
    tacticCol('initial-access', 'Initial Access', [T1190, T1566]),
    tacticCol('execution', 'Execution', [T1059]),
    tacticCol('credential-access', 'Credential Access', [T1003]),
  ],
  // T1190 is used by a group but has no defensive signal -> critical risk.
  groupsByTechnique: new Map([[T1190.id, [{}]], [T1003.id, [{}, {}]]]),
  mitigationsByTechnique: new Map([[T1003.id, [{}, {}, {}]], [T1059.id, [{}]]]),
};

const WIDGETS: DashboardWidget[] = [
  { id: 'coverage-summary', label: 'Coverage', icon: '', visible: true, order: 2 },
  { id: 'tactic-breakdown', label: 'Tactics', icon: '', visible: false, order: 1 },
  { id: 'gap-summary', label: 'Gaps', icon: '', visible: true, order: 0 },
];

describe('DashboardPanelComponent', () => {
  let fixture: ComponentFixture<DashboardPanelComponent>;
  let component: DashboardPanelComponent;
  let status$: BehaviorSubject<Map<string, string>>;
  let atomicLoaded$: BehaviorSubject<boolean>;
  let totalsSpy: jasmine.Spy;

  beforeEach(() => {
    status$ = new BehaviorSubject(new Map<string, string>());
    atomicLoaded$ = new BehaviorSubject<boolean>(false);
    const loaded = () => new BehaviorSubject<boolean>(false);
    totalsSpy = jasmine.createSpy('totals').and.returnValue({
      total: 4, enriched: 2, mitigation: 2, detection: 1, atomic: 0, d3fend: 0, control: 1, threatIntel: 2, cve: 1, defended: 2,
    });

    TestBed.configureTestingModule({
      imports: [DashboardPanelComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: DataService, useValue: { domain$: new BehaviorSubject(DOMAIN) } },
        { provide: PanelNavService, useValue: { open: jasmine.createSpy('open') } },
        { provide: EnrichmentService, useValue: {
            totals: totalsSpy,
            isEnriched: (t: Technique) => ENRICHED.has(t.attackId),
            hasDefensiveSignal: (t: Technique) => ENRICHED.has(t.attackId),
        } },
        { provide: ImplementationService, useValue: {
            status$,
            summarize: () => ({ implemented: 2, 'in-progress': 1, planned: 1, 'not-started': 0, untracked: 2 }),
        } },
        { provide: TimelineService, useValue: { getAll: () => [{ coveragePct: 40 }, { coveragePct: 50 }] } },
        { provide: AttackCveService, useValue: {
            loaded$: loaded(),
            getKevCvesForTechnique: (id: string) => (id === 'T1190' ? [{ cveId: 'CVE-2024-0001' }] : []),
            getCvesForTechnique: (id: string) => (id === 'T1190' ? [{ cveId: 'CVE-2024-0001' }] : []),
        } },
        { provide: CARService, useValue: { loaded$: loaded(), getAnalytics: (id: string) => (id === 'T1059' ? [{}] : []) } },
        { provide: AtomicService, useValue: { loaded$: atomicLoaded$, getTestCount: () => 0 } },
        { provide: D3fendService, useValue: { loaded$: loaded(), getCountermeasures: () => [] } },
        { provide: DashboardConfigService, useValue: { widgets$: new BehaviorSubject(WIDGETS) } },
        { provide: SigmaService, useValue: { loaded$: loaded(), getRuleCount: (id: string) => (id === 'T1059' ? 5 : 0) } },
        { provide: ElasticService, useValue: { loaded$: loaded(), getRuleCount: () => 0 } },
        { provide: SplunkContentService, useValue: { loaded$: loaded(), getRuleCount: () => 1 } },
        { provide: CveService, useValue: { getKevEntry: () => undefined } },
        { provide: MispService, useValue: { loaded$: loaded(), total$: new BehaviorSubject(12) } },
        { provide: OpenCtiService, useValue: { connected$: new BehaviorSubject(true) } },
      ],
    });
    fixture = TestBed.createComponent(DashboardPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('computes the headline coverage, posture and risk numbers from the loaded domain', () => {
    const s = component.stats!;
    expect(component.loading).toBeFalse();
    expect(s.totalTechniques).toBe(4);               // parents only
    expect(s.coveredTechniques).toBe(2);
    expect(s.coveragePct).toBe(50);
    expect(s.uncoveredCount).toBe(2);
    expect(s.mitigationCoveragePct).toBe(50);
    expect(s.controlCoveragePct).toBe(25);
    expect(s.detectionCoveragePct).toBe(25);         // only T1059 has a CAR analytic
    expect(s.withCarCount).toBe(1);
    expect(s.implementedCount).toBe(2);
    expect(s.totalMitigations).toBe(6);
    expect(s.criticalRiskCount).toBe(1);             // T1190: used by a group, undefended
    expect(s.topRiskTechniques.map(t => t.attackId)).toEqual(['T1190']);
    expect(s.cveExposedCount).toBe(1);
    expect(s.sigmaRuleCount).toBe(5);
    expect(s.splunkRuleCount).toBe(4);
    expect(s.threatGroupCount).toBe(2);
    expect(s.avgMitigations).toBe(2);                // (3 + 1) / 2 covered techniques
    // 0.2*0.5 + 0.2*0.25 + 0.2*0.25 + 0.15*0 + 0.15*0.75 + 0.10*0.75 = 38.75 -> 39
    expect(s.postureScore).toBe(39);
    expect(component.overallGrade).toBe('D');
    expect(component.riskLevel).toBe('high');
  });

  it('orders the tactic breakdown worst-first and reads the trend from the last two snapshots', () => {
    const s = component.stats!;
    expect(s.tacticStats.map(t => `${t.shortname}:${t.pct}`)).toEqual([
      'initial-access:0',
      'execution:100',
      'credential-access:100',
    ]);
    expect(s.hasTrendData).toBeTrue();
    expect(s.coverageTrend).toBe(10);
    expect(component.trendSign(s.coverageTrend)).toBe('+');
  });

  it('folds the async intel sources into the stats after the first build', () => {
    expect(component.stats?.mispClusterCount).toBe(12);
    expect(component.stats?.openctiConnected).toBeTrue();
  });

  it('renders the visible widgets in configured order', () => {
    expect(component.visibleWidgets.map(w => w.id)).toEqual(['gap-summary', 'coverage-summary']);
    expect(component.allWidgets.map(w => w.id)).toEqual(['gap-summary', 'tactic-breakdown', 'coverage-summary']);
    expect(component.isWidgetVisible('tactic-breakdown')).toBeFalse();
    expect(fixture.nativeElement.querySelectorAll('.widget-card').length).toBeGreaterThan(0);
  });

  it('rebuilds the stats when implementation status changes', () => {
    const before = totalsSpy.calls.count();
    status$.next(new Map([['course-of-action--x', 'implemented']]));
    expect(totalsSpy.calls.count()).toBe(before + 1);
  });

  it('tracks data-source health as each loader reports in', () => {
    const atomic = () => component.healthEntries.find(h => h.name === 'Atomic Red Team')!;
    expect(atomic().status).toBe('loading');
    atomicLoaded$.next(true);
    expect(atomic().status).toBe('loaded');
    expect(component.healthEntries.filter(h => h.status === 'loaded').length).toBe(1);
  });

  it('grades the composite posture, not mitigation coverage alone', () => {
    const grade = (postureScore: number) => {
      component.stats = { ...component.stats!, postureScore };
      return component.overallGrade;
    };
    expect(grade(80)).toBe('A');
    expect(grade(65)).toBe('B');
    expect(grade(50)).toBe('C');
    expect(grade(35)).toBe('D');
    expect(grade(34)).toBe('F');
    component.stats = { ...component.stats!, postureScore: 90, criticalRiskCount: 60 };
    expect(component.riskLevel).toBe('critical');
  });

  it('picks a technique of the day from the loaded parents', () => {
    expect(component.todTechnique).not.toBeNull();
    expect(component.todTechnique!.isSubtechnique).toBeFalse();
    expect(DOMAIN.techniques).toContain(component.todTechnique!);
  });
});
