// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
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
        provideHttpClient(),
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

  it('renders one item per workspace plus Help and Settings', () => {
    const items = fixture.nativeElement.querySelectorAll('.nav-item');
    // 8 workspaces + Help + Settings
    expect(items.length).toBe(10);
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
  });

  it('labels are human words, not shouty abbreviations', () => {
    const labels = [...fixture.nativeElement.querySelectorAll('.nav-label')].map(
      (el: any) => el.textContent.trim(),
    );
    expect(labels).toEqual([
      'Matrix', 'Dashboard', 'Intel', 'Detect', 'Exposure', 'Coverage',
      'Library', 'Reports', 'Help', 'Settings',
    ]);
  });

  it('renders SVG icons (no emoji glyphs)', () => {
    const icons = fixture.nativeElement.querySelectorAll('.nav-item app-icon svg');
    expect(icons.length).toBe(10);
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
