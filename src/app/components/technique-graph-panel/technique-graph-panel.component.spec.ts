// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TechniqueGraphPanelComponent, GraphNode } from './technique-graph-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { GraphFocusService } from '../../services/graph-focus.service';
import { Technique } from '../../models/technique';
import { ThreatGroup } from '../../models/group';
import { Domain } from '../../models/domain';

const TECH: Technique = {
  id: 'attack-pattern--t1',
  attackId: 'T1059',
  name: 'Command and Scripting Interpreter',
  isSubtechnique: false,
  parentId: null,
  subtechniques: [],
  tacticShortnames: [],
  capecIds: [],
} as unknown as Technique;

const GROUP: ThreatGroup = {
  id: 'intrusion-set--g1',
  attackId: 'G0001',
  name: 'APT-Test',
} as unknown as ThreatGroup;

function makeDomain(): Domain {
  return {
    techniques: [TECH],
    groups: [GROUP],
    software: [],
    mitigations: [],
    campaigns: [],
    mitigationsByTechnique: new Map(),
    groupsByTechnique: new Map(),
    softwareByTechnique: new Map(),
    campaignsByTechnique: new Map(),
    softwareByGroup: new Map(),
  } as unknown as Domain;
}

function groupNode(): GraphNode {
  return { id: GROUP.id, label: GROUP.attackId, kind: 'group', x: 0, y: 0 };
}

describe('TechniqueGraphPanelComponent', () => {
  let component: TechniqueGraphPanelComponent;
  let fixture: ComponentFixture<TechniqueGraphPanelComponent>;
  let selectedTechnique$: BehaviorSubject<Technique | null>;

  beforeEach(() => {
    selectedTechnique$ = new BehaviorSubject<Technique | null>(null);

    TestBed.configureTestingModule({
      imports: [TechniqueGraphPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            selectedTechnique$,
            setActivePanel: jasmine.createSpy(),
            selectTechnique: jasmine.createSpy('selectTechnique'),
            toggleThreatGroup: jasmine.createSpy('toggleThreatGroup'),
        }},
        { provide: DataService, useValue: {
            domain$: new BehaviorSubject<Domain | null>(makeDomain()),
            // Reverse-lookup getters exercised by the non-technique build paths.
            getTechniquesForGroup: (id: string) => (id === GROUP.id ? [TECH] : []),
            getSoftwareForGroup: () => [],
            getCampaignsForGroup: () => [],
            getTechniquesForSoftware: () => [],
            getGroupsForSoftware: () => [],
            getTechniquesForCampaign: () => [],
            getSoftwareForCampaign: () => [],
            getTechniquesForMitigation: () => [],
        }},
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], loaded$: new BehaviorSubject(true) } },
        { provide: PanelNavService, useValue: { open: jasmine.createSpy('open') } },
        GraphFocusService,
      ],
    });
    fixture = TestBed.createComponent(TechniqueGraphPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('starts with no focus', () => {
    expect(component.focus).toBeNull();
    expect(component.focusHistory.length).toBe(0);
  });

  it('centers the graph on a group (reverse-index neighbours)', () => {
    component.centerOnNode(groupNode());

    expect(component.focus).toEqual({ kind: 'group', id: GROUP.id });
    const center = component.nodes.find(n => n.pinned);
    expect(center?.id).toBe(GROUP.id);
    expect(center?.kind).toBe('group');
    // The group's technique appears as a neighbour node.
    expect(component.nodes.some(n => n.id === TECH.id && n.kind === 'technique')).toBeTrue();
  });

  it('goBack restores the prior focus', () => {
    // Start focused on a technique (external selection, focus was null → allowed).
    selectedTechnique$.next(TECH);
    expect(component.focus).toEqual({ kind: 'technique', id: TECH.id });

    // Pivot to a group, then step back.
    component.centerOnNode(groupNode());
    expect(component.focus?.kind).toBe('group');
    expect(component.focusHistory.length).toBe(1);

    component.goBack();
    expect(component.focus).toEqual({ kind: 'technique', id: TECH.id });
    expect(component.focusHistory.length).toBe(0);
  });

  it('guards a non-technique focus from external technique selection', () => {
    component.centerOnNode(groupNode());
    expect(component.focus?.kind).toBe('group');

    // An external technique selection (matrix / sidebar) must NOT clobber the
    // group focus, though the tracked technique updates for later use.
    selectedTechnique$.next(TECH);

    expect(component.focus).toEqual({ kind: 'group', id: GROUP.id });
    expect(component.nodes.find(n => n.pinned)?.kind).toBe('group');
    expect(component.technique).toBe(TECH);
  });

  it('an in-graph search pick re-centers even from a non-technique focus', () => {
    component.centerOnNode(groupNode());
    expect(component.focus?.kind).toBe('group');

    component.selectSearchResult(TECH);

    expect(component.focus).toEqual({ kind: 'technique', id: TECH.id });
    expect(component.focusHistory.length).toBe(1);
  });
});
