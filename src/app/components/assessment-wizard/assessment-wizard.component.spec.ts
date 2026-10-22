// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject, of } from 'rxjs';
import { AssessmentWizardComponent } from './assessment-wizard.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { EpssService } from '../../services/epss.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { ThreatGroup } from '../../models/group';

describe('AssessmentWizardComponent', () => {
  let component: AssessmentWizardComponent;
  let fixture: ComponentFixture<AssessmentWizardComponent>;

  beforeEach(() => {
    const emptyProfile = { source: { kind: 'top-groups' as const, n: 20 }, parentTechniqueIds: new Set<string>() };
    TestBed.configureTestingModule({
      imports: [AssessmentWizardComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: CveService, useValue: { kev$: new BehaviorSubject([]), getCachedCves: () => [] } },
        { provide: EpssService, useValue: { fetchScores: () => ({ subscribe: () => {} }) } },
        { provide: ThreatProfileService, useValue: {
            get current() { return emptyProfile; },
            profile$: new BehaviorSubject(emptyProfile),
            setSource: jasmine.createSpy(),
            absentGroups: () => [], unresolvedGroups: () => [],
        }},
      ],
    });
    fixture = TestBed.createComponent(AssessmentWizardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});

// P2-10: denominators over the REAL ThreatProfileService (profile resolved against a
// synthetic domain). Covers the unique-count fix (multi-tactic) and the sub-only roll-up.
describe('AssessmentWizardComponent denominators (P2-10)', () => {
  function tech(id: string, attackId: string, tactics: string[], parentId: string | null = null): Technique {
    return {
      id, attackId, name: attackId, description: '', url: '', tacticShortnames: tactics,
      isSubtechnique: parentId !== null, parentId, subtechniques: [], mitigationCount: 0, platforms: [],
      dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
      systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
    };
  }
  const tcol = (shortname: string, name: string, techniques: Technique[]) => ({
    tactic: { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order: 0 },
    techniques,
  });
  const grp = (id: string, attackId: string) => ({ id, attackId, name: attackId, aliases: [] } as unknown as ThreatGroup);

  function mount(domain: Domain): { wiz: AssessmentWizardComponent; profile: ThreatProfileService } {
    TestBed.configureTestingModule({
      imports: [AssessmentWizardComponent],
      providers: [
        { provide: FilterService, useValue: { activePanel$: new BehaviorSubject<string | null>(null), setActivePanel: () => undefined } },
        { provide: DataService, useValue: {
            domain$: new BehaviorSubject(domain), getCurrentDomain: () => domain,
            getCurrentAttackDomain: () => 'enterprise', switchDomain: () => undefined,
        } },
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()), getStatus: () => null, setStatus: () => undefined } },
        { provide: CveService, useValue: { kevTechScores$: of(new Map()) } },
        { provide: EpssService, useValue: { fetchScores: () => ({ subscribe: () => undefined }) } },
        { provide: LibraryLayerService, useValue: { layerTechniqueIds: () => of([]), manifest: [] } },
        // ThreatProfileService is the REAL root service (resolves against the DataService stub).
      ],
    });
    const wiz = TestBed.createComponent(AssessmentWizardComponent).componentInstance;
    (wiz as unknown as { domain: Domain }).domain = domain;
    return { wiz, profile: TestBed.inject(ThreatProfileService) };
  }
  const build = (wiz: AssessmentWizardComponent) => (wiz as unknown as { buildAssessment(): void }).buildAssessment();
  const compute = (wiz: AssessmentWizardComponent) => (wiz as unknown as { computeResults(): void }).computeResults();

  afterEach(() => localStorage.clear());

  it('counts UNIQUE techniques across tactics (a multi-tactic technique is not double-counted)', () => {
    // T1078 sits in two tactics; group G uses it.
    const T1078 = tech('attack-pattern--t1078', 'T1078', ['persistence', 'defense-evasion']);
    const G = grp('intrusion-set--g', 'G0001');
    const domain = {
      name: 'Enterprise ATT&CK', attackVersion: '19.2', techniques: [T1078], groups: [G],
      techniquesByGroup: new Map([[G.id, [T1078]]]), groupsByTechnique: new Map([[T1078.id, [G]]]),
      tacticColumns: [tcol('persistence', 'Persistence', [T1078]), tcol('defense-evasion', 'Defense Evasion', [T1078])],
      campaigns: [], techniquesByCampaign: new Map(), campaignsByGroup: new Map(),
    } as unknown as Domain;
    const { wiz, profile } = mount(domain);

    profile.setSource({ kind: 'groups', ids: [G.id] });
    expect(profile.current.parentTechniqueIds.size).toBe(1);
    build(wiz);
    // Built into both tactics, but the counts dedupe by id.
    expect(wiz.tacticAssessments.length).toBe(2);
    expect(wiz.totalTechniques).toBe(1);

    for (const ta of wiz.tacticAssessments) for (const t of ta.techniques) wiz.setTechniqueStatus(t, 'implemented');
    expect(wiz.ratedTechniques).toBe(1);                  // unique, not 2
    expect(wiz.ratedTechniques).toBeLessThanOrEqual(wiz.totalTechniques);

    compute(wiz);
    expect(wiz.coverageCount).toBe(1);                    // unique, not 2
    expect(wiz.coverageCount).toBeLessThanOrEqual(wiz.totalAssessed);
    expect(wiz.coveragePercent).toBe(100);               // not 200
    expect(wiz.coveragePercent).toBeLessThanOrEqual(100);
  });

  it('rolls a group\'s sub-only technique use up to the parent (the parent is rated)', () => {
    const T1568 = tech('attack-pattern--t1568', 'T1568', ['command-and-control']);
    const T1568_001 = tech('attack-pattern--t1568-001', 'T1568.001', ['command-and-control'], 'attack-pattern--t1568');
    const G = grp('intrusion-set--menupass', 'G0045');
    const domain = {
      name: 'Enterprise ATT&CK', attackVersion: '19.2', techniques: [T1568, T1568_001], groups: [G],
      techniquesByGroup: new Map([[G.id, [T1568_001]]]),         // the only use is the sub
      groupsByTechnique: new Map([[T1568_001.id, [G]]]),
      tacticColumns: [tcol('command-and-control', 'Command and Control', [T1568, T1568_001])],
      campaigns: [], techniquesByCampaign: new Map(), campaignsByGroup: new Map(),
    } as unknown as Domain;
    const { wiz, profile } = mount(domain);

    profile.setSource({ kind: 'groups', ids: [G.id] });
    expect([...profile.current.parentTechniqueIds]).toEqual(['attack-pattern--t1568']);
    expect(wiz.totalTechniques).toBe(1);
    build(wiz);
    const rated = wiz.tacticAssessments.flatMap(ta => ta.techniques.map(t => t.attackId));
    expect(rated).toContain('T1568');     // the parent appears, though only the sub was used
    expect(rated).not.toContain('T1568.001');
  });
});
