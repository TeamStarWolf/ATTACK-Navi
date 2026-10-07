// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';
import { CollectionPanelComponent } from './collection-panel.component';
import { CustomTechniqueService } from '../../services/custom-technique.service';
import { CustomGroupService } from '../../services/custom-group.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { AnnotationService } from '../../services/annotation.service';
import { StixCollectionService } from '../../services/stix-collection.service';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { Tactic } from '../../models/tactic';

function tactic(shortname: string, name: string, order: number): Tactic {
  return { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order };
}

describe('CollectionPanelComponent', () => {
  let component: CollectionPanelComponent;
  let fixture: ComponentFixture<CollectionPanelComponent>;
  let domain$: BehaviorSubject<Domain | null>;

  beforeEach(async () => {
    domain$ = new BehaviorSubject<Domain | null>(null);
    const mockCustomTechniqueService = jasmine.createSpyObj(
      'CustomTechniqueService',
      ['getAll', 'create', 'update', 'delete'],
      {
        techniques$: of([]),
      }
    );
    mockCustomTechniqueService.getAll.and.returnValue([]);

    const mockCustomGroupService = jasmine.createSpyObj(
      'CustomGroupService',
      ['getAll'],
      {
        count$: of(0),
      }
    );
    mockCustomGroupService.getAll.and.returnValue([]);

    const mockCustomMitigationService = {
      all: [],
      mitigations$: of([]),
    };

    const mockAnnotationService = {
      all: new Map(),
      annotations$: of(new Map()),
    };

    const mockStixCollectionService = jasmine.createSpyObj(
      'StixCollectionService',
      ['exportCollection', 'parseBundle', 'importBundle', 'fetchAndParseUrl', 'parseImportFromHash']
    );
    mockStixCollectionService.parseImportFromHash.and.returnValue(null);

    await TestBed.configureTestingModule({
      imports: [CollectionPanelComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: CustomTechniqueService, useValue: mockCustomTechniqueService },
        { provide: CustomGroupService, useValue: mockCustomGroupService },
        { provide: CustomMitigationService, useValue: mockCustomMitigationService },
        { provide: AnnotationService, useValue: mockAnnotationService },
        { provide: StixCollectionService, useValue: mockStixCollectionService },
        { provide: DataService, useValue: { domain$ } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(CollectionPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('renders the panel', () => {
    const panel = fixture.nativeElement.querySelector('.panel');
    expect(panel).toBeTruthy();
  });

  it('checks the URL for a shared-collection import on init', () => {
    const stix = TestBed.inject(StixCollectionService) as any;
    expect(stix.parseImportFromHash).toHaveBeenCalled();
  });

  it('should show 3 tabs', () => {
    const tabs = fixture.nativeElement.querySelectorAll('.tab-btn');
    expect(tabs.length).toBe(3);

    const tabLabels = Array.from(tabs).map((t: any) => t.textContent.trim());
    expect(tabLabels).toContain('My Collection');
    expect(tabLabels).toContain('Import');
    expect(tabLabels).toContain('Custom Techniques');
  });

  it('should show export button on collection tab', () => {
    const exportBtn = fixture.nativeElement.querySelector('.action-btn.primary');
    expect(exportBtn).toBeTruthy();
    expect(exportBtn.textContent.trim()).toContain('Export STIX Bundle');
  });

  it('should show import file input on import tab', () => {
    component.setTab('import');
    fixture.detectChanges();
    const fileInput = fixture.nativeElement.querySelector('input[type="file"]');
    expect(fileInput).toBeTruthy();
    expect(fileInput.getAttribute('accept')).toBe('.json');
  });

  it('should render custom technique form on techniques tab', () => {
    component.setTab('techniques');
    fixture.detectChanges();
    const formTitle = fixture.nativeElement.querySelector('.section-title');
    expect(formTitle).toBeTruthy();
    expect(formTitle.textContent.trim()).toBe('New Technique');
  });

  describe('custom-technique tactic picker (ATT&CK v19 currency)', () => {
    it('offers the Enterprise v19 tactics before a domain loads, never the retired defense-evasion slug', () => {
      expect(component.allTactics).toContain('stealth');
      expect(component.allTactics).toContain('defense-impairment');
      expect(component.allTactics).not.toContain('defense-evasion');
    });

    it('follows the loaded domain tactics in matrix order and labels them with the domain names', () => {
      component.setTab('techniques');
      // domain$ marks the OnPush view for check, so one detectChanges renders both the tab and the picker
      domain$.next({
        tactics: [
          tactic('impact', 'Impact', 2),
          tactic('defense-evasion', 'Defense Evasion', 1),
          tactic('initial-access', 'Initial Access', 0),
        ],
      } as unknown as Domain);
      fixture.detectChanges();
      expect(component.allTactics).toEqual(['initial-access', 'defense-evasion', 'impact']);
      expect(component.tacticName('defense-evasion')).toBe('Defense Evasion');

      const labels = Array.from(fixture.nativeElement.querySelectorAll('.checkbox-grid:not(.platforms) .checkbox-label span'))
        .map((el: any) => el.textContent.trim());
      expect(labels).toEqual(['Initial Access', 'Defense Evasion', 'Impact']);
    });

    it('rebuilds the picker when the domain switches to Enterprise v19', () => {
      domain$.next({ tactics: [tactic('stealth', 'Stealth', 0), tactic('defense-impairment', 'Defense Impairment', 1)] } as unknown as Domain);
      expect(component.allTactics).toEqual(['stealth', 'defense-impairment']);
      expect(component.tacticName('stealth')).toBe('Stealth');
    });
  });

  it('should switch tabs when tab buttons are clicked', () => {
    const tabs = fixture.nativeElement.querySelectorAll('.tab-btn');
    // Click "Import" tab
    tabs[1].click();
    fixture.detectChanges();
    expect(component.activeTab).toBe('import');

    // Click "Custom Techniques" tab
    tabs[2].click();
    fixture.detectChanges();
    expect(component.activeTab).toBe('techniques');
  });
});
