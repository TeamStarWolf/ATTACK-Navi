// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { NavRailComponent } from './nav-rail.component';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';

describe('NavRailComponent', () => {
  let component: NavRailComponent;
  let fixture: ComponentFixture<NavRailComponent>;
  let newKevCount$: BehaviorSubject<number>;

  beforeEach(async () => {
    newKevCount$ = new BehaviorSubject<number>(0);

    const mockCveService = jasmine.createSpyObj('CveService', ['dismissKevBadge'], {
      newKevCount$: newKevCount$.asObservable(),
    });

    await TestBed.configureTestingModule({
      imports: [NavRailComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: CveService, useValue: mockCveService },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(NavRailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('renders the viewpoint selector at the top of the rail', () => {
    const selector = fixture.nativeElement.querySelector('app-viewpoint-selector');
    expect(selector).toBeTruthy();
    // It sits above the Workspaces section label, not among the nav items.
    expect(fixture.nativeElement.querySelector('.rail-viewpoint')).toBeTruthy();
    expect(selector.querySelector('.nav-item')).toBeFalsy();
  });

  it('renders one item per workspace plus Help and Settings', () => {
    const items = fixture.nativeElement.querySelectorAll('.nav-item');
    // 9 workspaces + Help + Settings
    expect(items.length).toBe(11);
  });

  it('workspace items are router links with the workspace root path', () => {
    const links = [...fixture.nativeElement.querySelectorAll('.nav-list a.nav-item')] as HTMLAnchorElement[];
    const hrefs = links.map(a => a.getAttribute('href'));
    expect(hrefs).toContain('/matrix');
    expect(hrefs).toContain('/intel');
    expect(hrefs).toContain('/detect');
    expect(hrefs).toContain('/exposure');
    expect(hrefs).toContain('/coverage');
    expect(hrefs).toContain('/library');
    expect(hrefs).toContain('/reports');
    expect(hrefs).toContain('/dashboard');
    expect(hrefs).toContain('/status');
  });

  it('labels are human words, not shouty abbreviations', () => {
    const labels = [...fixture.nativeElement.querySelectorAll('.nav-label')].map(
      (el: any) => el.textContent.trim(),
    );
    // Grouped rail order: Threat & Exposure, then Response, then Reference, then Help/Settings.
    expect(labels).toEqual([
      'Matrix', 'Exposure', 'Intel', 'Detect', 'Coverage',
      'Dashboard', 'Reports', 'Library', 'Status', 'Help', 'Settings',
    ]);
  });

  it('renders SVG icons (no emoji glyphs)', () => {
    // Every icon host in the rail (drag grips + workspace icons + Help/Settings)
    // must render an inline SVG — i.e. no emoji/text glyphs.
    const iconHosts = fixture.nativeElement.querySelectorAll('.nav-item app-icon');
    const svgs = fixture.nativeElement.querySelectorAll('.nav-item app-icon svg');
    expect(iconHosts.length).toBeGreaterThan(0);
    expect(svgs.length).toBe(iconHosts.length);
  });

  it('shows the KEV badge on Exposure when newKevCount > 0', () => {
    newKevCount$.next(5);
    fixture.detectChanges();
    const badge = fixture.nativeElement.querySelector('.nav-badge');
    expect(badge).toBeTruthy();
    expect(badge.textContent).toContain('+5');
    expect(badge.closest('.nav-item').getAttribute('aria-label')).toBe('Exposure');
  });

  it('hides the KEV badge when newKevCount is 0', () => {
    newKevCount$.next(0);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.nav-badge')).toBeFalsy();
  });

  it('emits helpClick when the Help button is clicked', () => {
    spyOn(component.helpClick, 'emit');
    fixture.nativeElement.querySelector('.help-btn').click();
    expect(component.helpClick.emit).toHaveBeenCalled();
  });

  it('clicking Settings clears the version dot', () => {
    component.newVersionAvailable = true;
    component.onSettingsClick();
    expect(component.newVersionAvailable).toBe(false);
  });
});
