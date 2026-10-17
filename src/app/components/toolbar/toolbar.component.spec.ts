// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject, of } from 'rxjs';
import { ToolbarComponent } from './toolbar.component';
import { FilterService } from '../../services/filter.service';
import { AttackUpdateState, DataService } from '../../services/data.service';
import { SavedViewsService } from '../../services/saved-views.service';
import { CommandPaletteService } from '../../services/command-palette.service';

describe('ToolbarComponent', () => {
  let component: ToolbarComponent;
  let fixture: ComponentFixture<ToolbarComponent>;
  let mockFilterService: jasmine.SpyObj<FilterService>;
  let mockDataService: jasmine.SpyObj<DataService>;
  let mockSavedViewsService: jasmine.SpyObj<SavedViewsService>;
  let mockPalette: jasmine.SpyObj<CommandPaletteService>;
  let update$: BehaviorSubject<AttackUpdateState>;

  beforeEach(async () => {
    mockFilterService = jasmine.createSpyObj('FilterService', ['setTechniqueQuery']);

    update$ = new BehaviorSubject<AttackUpdateState>({ status: 'idle' });
    mockDataService = jasmine.createSpyObj(
      'DataService',
      ['fetchDomain', 'pinnedVersion', 'checkForUpdate', 'applyUpdate', 'dismissUpdate', 'revertToPinned', 'setDataSourceMode', 'loadDomain', 'getCurrentAttackDomain'],
      {
        loading$: of(false),
        domain$: of({ attackVersion: '19.2', attackModified: '2026-08-05T21:33:58.496Z' }),
        update$,
        freshness$: new BehaviorSubject<'bundled' | 'cached' | 'live' | null>('bundled'),
        currentDomain$: new BehaviorSubject('enterprise'),
      },
    );
    mockDataService.pinnedVersion.and.returnValue('19.2');
    mockDataService.getCurrentAttackDomain.and.returnValue('enterprise');

    mockSavedViewsService = jasmine.createSpyObj('SavedViewsService', ['saveCurrentView', 'deleteView'], {
      views$: of([]),
    });

    mockPalette = jasmine.createSpyObj('CommandPaletteService', ['open', 'close', 'toggle']);

    await TestBed.configureTestingModule({
      imports: [ToolbarComponent],
      providers: [
        provideHttpClient(withXhr()),
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

  it('should render domain buttons (Enterprise, ICS, Mobile, F3)', () => {
    const domainBtns = fixture.nativeElement.querySelectorAll('.domain-btn');
    expect(domainBtns.length).toBe(4);
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

  it('carries the vintage chip (E1.4): the pinned version and bundle date, linking to data health', () => {
    const chip = fixture.nativeElement.querySelector('app-vintage-chip [data-testid="vintage-chip"]') as HTMLAnchorElement;
    expect(chip).toBeTruthy();
    expect(chip.textContent!.replace(/\s+/g, ' ').trim()).toBe('ATT&CK v19.2 pinned 2026-08-05');
    expect(chip.getAttribute('href')).toBe('/status');
    // The brand no longer carries a bare version badge of its own.
    expect(fixture.nativeElement.querySelectorAll('.attack-version').length).toBe(1);
  });

  describe('ATT&CK pinning (E1.4, decision D2)', () => {
    const offer = () => fixture.nativeElement.querySelector('[data-testid="attack-update"]') as HTMLElement;
    const show = (state: AttackUpdateState) => { update$.next(state); fixture.detectChanges(); };
    const buttons = () => Array.from(offer().querySelectorAll('button')) as HTMLButtonElement[];

    it('has no live/bundled toggle; the one ATT&CK action is "Check for ATT&CK update"', () => {
      expect(fixture.nativeElement.querySelector('.source-mode-btn')).toBeNull();
      const check = fixture.nativeElement.querySelector('button[aria-label="Check for ATT&CK update"]') as HTMLButtonElement;
      expect(check).toBeTruthy();
      expect(check.title).toContain('19.2');
      check.click();
      expect(mockDataService.checkForUpdate).toHaveBeenCalledTimes(1);
      expect(mockDataService.loadDomain).not.toHaveBeenCalled();
      expect(mockDataService.setDataSourceMode).not.toHaveBeenCalled();
    });

    it('keeps a polite status region in the DOM so each check state is announced', () => {
      expect(offer()).toBeTruthy();
      expect(offer().getAttribute('role')).toBe('status');
      expect(offer().getAttribute('aria-live')).toBe('polite');
      expect(offer().textContent!.trim()).toBe('');
      show({ status: 'checking', pinnedVersion: '19.2' });
      expect(offer().textContent).toContain('Checking MITRE');
    });

    it('offers a newer release for this session only and applies it only on click', () => {
      show({ status: 'available', pinnedVersion: '19.2', liveVersion: '20.0' });
      expect(offer().textContent).toContain('ATT&CK 20.0 is available');
      expect(offer().textContent).toContain('pinned to 19.2');
      expect(offer().textContent).toContain('this session only');
      expect(mockDataService.applyUpdate).not.toHaveBeenCalled();
      const [use, keep] = buttons();
      expect(use.textContent!.trim()).toBe('Use 20.0 for this session');
      expect(keep.textContent!.trim()).toBe('Keep 19.2');
      keep.click();
      expect(mockDataService.dismissUpdate).toHaveBeenCalled();
      use.click();
      expect(mockDataService.applyUpdate).toHaveBeenCalledTimes(1);
    });

    it('says when the pinned release is current, when the check failed, and how to go back after applying', () => {
      show({ status: 'up-to-date', pinnedVersion: '19.2', liveVersion: '19.2' });
      expect(offer().textContent).toContain('No newer release');

      show({ status: 'failed', pinnedVersion: '19.2', error: 'network error' });
      expect(offer().textContent).toContain('Could not check for an ATT&CK update: network error');
      expect(offer().textContent).toContain('stays on 19.2 (pinned)');
      buttons()[0].click();
      expect(mockDataService.checkForUpdate).toHaveBeenCalled();

      show({ status: 'applied', pinnedVersion: '19.2', liveVersion: '20.0' });
      expect(offer().textContent).toContain('Using ATT&CK 20.0 for this session only');
      const back = buttons()[0];
      expect(back.textContent!.trim()).toBe('Back to 19.2');
      back.click();
      expect(mockDataService.revertToPinned).toHaveBeenCalled();
    });
  });
});
