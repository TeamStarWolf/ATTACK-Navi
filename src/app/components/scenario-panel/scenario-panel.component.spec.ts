// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture, fakeAsync, tick } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ScenarioPanelComponent } from './scenario-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { PostureService } from '../../services/posture.service';
import { ThreatSimulationService } from '../../services/threat-simulation.service';
import { EmulationPlanService } from '../../services/emulation-plan.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { Technique } from '../../models/technique';
import { ThreatGroup } from '../../models/group';
import { PostureBucket } from '../../models/posture/posture.types';

function tech(id: string, attackId: string): Technique {
  return {
    id, attackId, name: attackId, description: '', url: '', tacticShortnames: ['execution'],
    isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  };
}

const GROUP = { id: 'intrusion-set--g1', attackId: 'G0001', name: 'TestAPT', aliases: [] } as unknown as ThreatGroup;
const T1 = tech('t1', 'T1001');
const T2 = tech('t2', 'T1002');
const DOMAIN = { groups: [GROUP], techniques: [T1, T2], campaigns: [], mitigationsByTechnique: new Map() } as any;

describe('ScenarioPanelComponent (posture outcomes)', () => {
  let component: ScenarioPanelComponent;
  let fixture: ComponentFixture<ScenarioPanelComponent>;
  let domain$: BehaviorSubject<any>;
  let buckets: Map<string, PostureBucket>;
  let ownerWords: boolean;

  function configure(): void {
    domain$ = new BehaviorSubject<any>(DOMAIN);
    TestBed.configureTestingModule({
      imports: [ScenarioPanelComponent],
      providers: [
        // scenario-panel deps
        { provide: FilterService, useValue: { selectTechnique: jasmine.createSpy('selectTechnique'), toggleThreatGroup: jasmine.createSpy() } },
        { provide: DataService, useValue: {
            domain$,
            getCurrentDomain: () => domain$.value,
            getCurrentAttackDomain: () => 'enterprise',
            getTechniquesForGroup: (id: string) => (id === GROUP.id ? [T1, T2] : []),
        } },
        { provide: PostureService, useValue: {
            stateFor: (t: Technique) => ({ bucket: buckets.get(t.id) ?? 'none' }),
            ownerWords: () => ownerWords,
        } },
        { provide: ThreatSimulationService, useValue: { simulate: () => ({ techniquesCovered: 0, techniquesTotal: 0, coveragePercent: 0, gaps: [], riskScore: 0, tacticBreakdown: [] }) } },
        { provide: EmulationPlanService, useValue: { generatePlan: () => ({ steps: [] }), exportCalderaProfile: () => {} } },
        // embedded picker deps
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]), layerTechniqueIds: () => new BehaviorSubject([]), manifest: [] } },
        { provide: ThreatProfileService, useValue: {
            get current() { return { source: { kind: 'top-groups', n: 20 } }; },
            profile$: new BehaviorSubject({ source: { kind: 'top-groups', n: 20 } }),
            setSource: jasmine.createSpy('setSource'),
        } },
      ],
    });
    fixture = TestBed.createComponent(ScenarioPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  }

  beforeEach(() => { buckets = new Map(); ownerWords = false; });

  it('is created', () => {
    configure();
    expect(component).toBeTruthy();
  });

  it('a fresh profile shows only Known + None, renders no Covered/Proven card, and no "covered"/"proven" text', fakeAsync(() => {
    ownerWords = false;                 // no owner words → fresh profile
    buckets = new Map([['t1', 'known'], ['t2', 'none']]);
    configure();

    component.onGroupPicked(GROUP.id);
    tick(200);                          // flush the simulate() setTimeout
    fixture.detectChanges();

    expect(component.result!.hasOwnerWords).toBeFalse();
    expect(component.result!.covered).toBe(0);
    expect(component.result!.proven).toBe(0);

    const host = fixture.nativeElement as HTMLElement;
    // No Covered or Proven card is rendered.
    expect(host.querySelector('.outcome-covered')).toBeNull();
    expect(host.querySelector('.outcome-proven')).toBeNull();
    // The fresh-profile prompt is shown.
    expect(host.textContent).toContain('Record a run or mark a mitigation implemented');
    // No 'covered'/'proven' anywhere in visible text or in title/aria-label/placeholder/alt.
    expect(host.textContent!.toLowerCase()).not.toContain('covered');
    expect(host.textContent!.toLowerCase()).not.toContain('proven');
    for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
      for (const el of Array.from(host.querySelectorAll(`[${attr}]`))) {
        const v = (el.getAttribute(attr) ?? '').toLowerCase();
        expect(v).not.toContain('covered');
        expect(v).not.toContain('proven');
      }
    }
  }));

  it('with owner words, the Covered and Proven cards render with the vocabulary labels', fakeAsync(() => {
    ownerWords = true;
    buckets = new Map([['t1', 'covered'], ['t2', 'proven']]);
    configure();

    component.onGroupPicked(GROUP.id);
    tick(200);
    fixture.detectChanges();

    expect(component.result!.covered).toBe(1);
    expect(component.result!.proven).toBe(1);
    const host = fixture.nativeElement as HTMLElement;
    expect(host.querySelector('.outcome-covered')).not.toBeNull();
    expect(host.querySelector('.outcome-proven')).not.toBeNull();
    // Labels come from scenarioOutcomeLabel() — 'Covered (self-attested or range)'.
    expect(host.textContent).toContain('Covered (self-attested or range)');
  }));
});
