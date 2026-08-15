// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { ToolbarComponent } from './toolbar.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { SavedViewsService } from '../../services/saved-views.service';
import { CommandPaletteService } from '../../services/command-palette.service';

describe('ToolbarComponent', () => {
  let component: ToolbarComponent;
  let fixture: ComponentFixture<ToolbarComponent>;
  let mockFilterService: jasmine.SpyObj<FilterService>;
  let mockDataService: jasmine.SpyObj<DataService>;
  let mockSavedViewsService: jasmine.SpyObj<SavedViewsService>;
  let mockPalette: jasmine.SpyObj<CommandPaletteService>;

  beforeEach(async () => {
    mockFilterService = jasmine.createSpyObj('FilterService', ['setTechniqueQuery']);

    mockDataService = jasmine.createSpyObj('DataService', ['fetchDomain'], {
      loading$: of(false),
      domain$: of(null),
    });

    mockSavedViewsService = jasmine.createSpyObj('SavedViewsService', ['saveCurrentView', 'deleteView'], {
      views$: of([]),
    });

    mockPalette = jasmine.createSpyObj('CommandPaletteService', ['open', 'close', 'toggle']);

    await TestBed.configureTestingModule({
      imports: [ToolbarComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: FilterService, useValue: mockFilterService },
        { provide: DataService, useValue: mockDataService },
        { provide: SavedViewsService, useValue: mockSavedViewsService },
        { provide: CommandPaletteService, useValue: mockPalette },
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

  it('should emit domainChange when domain button clicked', () => {
    spyOn(component.domainChange, 'emit');
    const icsDomainBtn = fixture.nativeElement.querySelectorAll('.domain-btn')[1];
    icsDomainBtn.click();
    fixture.detectChanges();
    expect(component.domainChange.emit).toHaveBeenCalledWith('ics');
  });

  it('carries no matrix-scoped controls (they moved to the matrix page)', () => {
    expect(fixture.nativeElement.querySelector('.heatmap-btn')).toBeFalsy();
    expect(fixture.nativeElement.querySelector('.export-menu')).toBeFalsy();
    expect(fixture.nativeElement.querySelector('input.search-input')).toBeFalsy();
  });

  it('the search trigger opens the command palette', () => {
    const trigger = fixture.nativeElement.querySelector('.palette-trigger');
    expect(trigger).toBeTruthy();
    trigger.click();
    expect(mockPalette.open).toHaveBeenCalled();
  });

  it('brand links back to the matrix', () => {
    const brand = fixture.nativeElement.querySelector('a.brand-link');
    expect(brand).toBeTruthy();
    expect(brand.getAttribute('href')).toBe('/matrix');
  });
});
