import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';
import { CollectionPanelComponent } from './collection-panel.component';
import { FilterService } from '../../services/filter.service';
import { CustomTechniqueService } from '../../services/custom-technique.service';
import { CustomGroupService } from '../../services/custom-group.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { AnnotationService } from '../../services/annotation.service';
import { StixCollectionService } from '../../services/stix-collection.service';

describe('CollectionPanelComponent', () => {
  let component: CollectionPanelComponent;
  let fixture: ComponentFixture<CollectionPanelComponent>;
  let activePanel$: BehaviorSubject<string | null>;

  beforeEach(async () => {
    activePanel$ = new BehaviorSubject<string | null>('collection');

    const mockFilterService = jasmine.createSpyObj('FilterService', ['setActivePanel'], {
      activePanel$: activePanel$.asObservable(),
    });

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
      ['exportCollection', 'parseBundle', 'importBundle', 'fetchAndParseUrl']
    );

    await TestBed.configureTestingModule({
      imports: [CollectionPanelComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: FilterService, useValue: mockFilterService },
        { provide: CustomTechniqueService, useValue: mockCustomTechniqueService },
        { provide: CustomGroupService, useValue: mockCustomGroupService },
        { provide: CustomMitigationService, useValue: mockCustomMitigationService },
        { provide: AnnotationService, useValue: mockAnnotationService },
        { provide: StixCollectionService, useValue: mockStixCollectionService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(CollectionPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should be visible when activePanel is collection', () => {
    expect(component.visible).toBeTrue();
    const panel = fixture.nativeElement.querySelector('.panel');
    expect(panel).toBeTruthy();
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

  it('should hide when activePanel is not collection', () => {
    activePanel$.next(null);
    fixture.detectChanges();
    expect(component.visible).toBeFalse();
    const panel = fixture.nativeElement.querySelector('.panel');
    expect(panel).toBeFalsy();
  });
});
