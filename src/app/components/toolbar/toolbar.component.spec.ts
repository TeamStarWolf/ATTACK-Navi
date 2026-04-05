import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject, of } from 'rxjs';
import { ToolbarComponent } from './toolbar.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { SavedViewsService } from '../../services/saved-views.service';
import { AttackCveService } from '../../services/attack-cve.service';

describe('ToolbarComponent', () => {
  let component: ToolbarComponent;
  let fixture: ComponentFixture<ToolbarComponent>;
  let mockFilterService: jasmine.SpyObj<FilterService>;
  let mockDataService: jasmine.SpyObj<DataService>;
  let mockSavedViewsService: jasmine.SpyObj<SavedViewsService>;
  let mockAttackCveService: jasmine.SpyObj<AttackCveService>;

  beforeEach(async () => {
    mockFilterService = jasmine.createSpyObj('FilterService', [
      'setHeatmapMode',
      'setTechniqueQuery',
      'setSortMode',
      'setDimUncovered',
      'setPlatformFilter',
      'setActivePanel',
      'setSearchScope',
      'setSearchFilterMode',
      'setImplStatusFilter',
      'setActiveDataSource',
    ], {
      activeMitigationFilters$: of([]),
      techniqueQuery$: of(''),
      sortMode$: of('alpha' as const),
      dimUncovered$: of(false),
      platformFilter$: of(null),
      platformMulti$: of(new Set<string>()),
      activePanel$: of(null),
      activeThreatGroupIds$: of(new Set<string>()),
      heatmapMode$: of('coverage' as const),
      implStatusFilter$: of(null),
      searchScope$: of('name' as const),
      searchFilterMode$: of(false),
      activeDataSource$: of(null),
    });

    mockDataService = jasmine.createSpyObj('DataService', ['fetchDomain'], {
      loading$: of(false),
      domain$: of(null),
    });

    mockSavedViewsService = jasmine.createSpyObj('SavedViewsService', ['saveCurrentView', 'deleteView'], {
      views$: of([]),
    });

    mockAttackCveService = jasmine.createSpyObj('AttackCveService', ['getMappingForCve'], {
      loaded$: of(false),
    });

    await TestBed.configureTestingModule({
      imports: [ToolbarComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: FilterService, useValue: mockFilterService },
        { provide: DataService, useValue: mockDataService },
        { provide: SavedViewsService, useValue: mockSavedViewsService },
        { provide: AttackCveService, useValue: mockAttackCveService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ToolbarComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render domain buttons', () => {
    const domainBtns = fixture.nativeElement.querySelectorAll('.domain-btn');
    expect(domainBtns.length).toBe(3);
  });

  it('should render the heatmap dropdown button', () => {
    const heatmapBtn = fixture.nativeElement.querySelector('.heatmap-btn');
    expect(heatmapBtn).toBeTruthy();
    expect(heatmapBtn.textContent).toContain('Coverage');
  });

  it('should emit domainChange when domain button clicked', () => {
    spyOn(component.domainChange, 'emit');
    const icsDomainBtn = fixture.nativeElement.querySelectorAll('.domain-btn')[1];
    icsDomainBtn.click();
    fixture.detectChanges();
    expect(component.domainChange.emit).toHaveBeenCalledWith('ics');
  });

  it('should call setTechniqueQuery on search input', () => {
    const input = fixture.nativeElement.querySelector('.technique-search .search-input');
    expect(input).toBeTruthy();
    input.value = 'T1059';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(mockFilterService.setTechniqueQuery).toHaveBeenCalledWith('T1059');
  });

  it('should emit exportCsv when export menu item is clicked', () => {
    spyOn(component.exportCsv, 'emit');
    // Open the export menu
    component.showExportMenu = true;
    fixture.detectChanges();
    const exportBtn = fixture.nativeElement.querySelector('.export-menu .menu-action');
    expect(exportBtn).toBeTruthy();
    exportBtn.click();
    expect(component.exportCsv.emit).toHaveBeenCalled();
  });

  it('should render the search input', () => {
    const searchInput = fixture.nativeElement.querySelector('.search-input');
    expect(searchInput).toBeTruthy();
  });
});
