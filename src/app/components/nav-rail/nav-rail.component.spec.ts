// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { NAVRAIL_COLLAPSED_KEY, NavRailComponent, loadRailCollapsed, saveRailCollapsed } from './nav-rail.component';
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

describe('NavRailComponent: icon-only collapse', () => {
  let fixture: ComponentFixture<NavRailComponent>;
  let host: HTMLElement;

  const setup = async (wide = true): Promise<void> => {
    const realMatchMedia = window.matchMedia.bind(window);
    spyOn(window, 'matchMedia').and.callFake((q: string) =>
      q === '(width > 768px)'
        ? ({ matches: wide, media: q, addEventListener: () => {}, removeEventListener: () => {} } as unknown as MediaQueryList)
        : realMatchMedia(q));
    await TestBed.configureTestingModule({
      imports: [NavRailComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: CveService, useValue: { newKevCount$: new BehaviorSubject(0).asObservable() } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(NavRailComponent);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  };

  const toggle = (): HTMLButtonElement => host.querySelector('.rail-collapse-btn') as HTMLButtonElement;

  beforeEach(() => localStorage.removeItem(NAVRAIL_COLLAPSED_KEY));
  afterEach(() => localStorage.removeItem(NAVRAIL_COLLAPSED_KEY));

  it('persists the collapsed state under one key; expanded removes it', () => {
    expect(loadRailCollapsed()).toBeFalse();
    saveRailCollapsed(true);
    expect(localStorage.getItem(NAVRAIL_COLLAPSED_KEY)).toBe('1');
    expect(loadRailCollapsed()).toBeTrue();
    saveRailCollapsed(false);
    expect(localStorage.getItem(NAVRAIL_COLLAPSED_KEY)).toBeNull();
    localStorage.setItem(NAVRAIL_COLLAPSED_KEY, 'yes');
    expect(loadRailCollapsed()).toBeFalse();
  });

  it('treats blocked storage as expanded', () => {
    spyOn(Storage.prototype, 'getItem').and.throwError('SecurityError');
    expect(loadRailCollapsed()).toBeFalse();
  });

  it('the toggle controls the rail nav and starts expanded', async () => {
    await setup();
    const btn = toggle();
    const nav = host.querySelector('nav') as HTMLElement;
    expect(nav.id).toBe('app-nav-rail');
    expect(btn.getAttribute('aria-controls')).toBe('app-nav-rail');
    expect(btn.getAttribute('aria-expanded')).toBe('true');
    expect(btn.getAttribute('aria-label')).toBe('Collapse navigation');
    expect(btn.getAttribute('title')).toBe('Collapse navigation');
    expect(host.classList).not.toContain('collapsed');
  });

  it('collapsing shows icons with the workspace name as title and aria-label, and persists', async () => {
    await setup();
    toggle().click();
    fixture.detectChanges();
    const btn = toggle();
    expect(btn.getAttribute('aria-expanded')).toBe('false');
    expect(btn.getAttribute('aria-label')).toBe('Expand navigation');
    expect(host.classList).toContain('collapsed');
    expect(localStorage.getItem(NAVRAIL_COLLAPSED_KEY)).toBe('1');

    const items = [...host.querySelectorAll('.nav-list a.nav-item')] as HTMLElement[];
    expect(items.length).toBe(9);
    for (const a of items) {
      expect(a.getAttribute('title')).toBe(a.getAttribute('aria-label'));
      expect(a.querySelector('.nav-icon svg')).toBeTruthy();
    }
    // Section groupings stay (as separators); Help and Settings stay at the bottom.
    expect(host.querySelectorAll('.rail-section-label').length).toBe(3);
    expect(host.querySelectorAll('.nav-items-bottom .nav-item').length).toBe(2);
    // The viewpoint selector collapses to its icon.
    expect(host.querySelector('app-viewpoint-selector')?.classList).toContain('compact');

    toggle().click();
    fixture.detectChanges();
    expect(host.classList).not.toContain('collapsed');
    expect(toggle().getAttribute('aria-expanded')).toBe('true');
    expect(localStorage.getItem(NAVRAIL_COLLAPSED_KEY)).toBeNull();
    expect(items[0].getAttribute('title')).toContain('drag to reorder');
  });

  it('applies a stored collapsed state on the first render', async () => {
    localStorage.setItem(NAVRAIL_COLLAPSED_KEY, '1');
    await setup();
    expect(host.classList).toContain('collapsed');
    expect(toggle().getAttribute('aria-expanded')).toBe('false');
  });

  it('keeps the bottom bar unchanged at 768 px or less, even when collapsed is stored', async () => {
    localStorage.setItem(NAVRAIL_COLLAPSED_KEY, '1');
    await setup(false);
    expect(host.classList).not.toContain('collapsed');
    expect(host.querySelector('app-viewpoint-selector')?.classList).not.toContain('compact');
    const first = host.querySelector('.nav-list a.nav-item') as HTMLElement;
    expect(first.getAttribute('title')).toContain('drag to reorder');
  });

  it('keeps the focus order: viewpoint, toggle, workspaces, Help, Settings', async () => {
    await setup();
    toggle().click();
    fixture.detectChanges();
    const focusables = [...host.querySelectorAll('button, a[href]')] as HTMLElement[];
    expect(focusables[0].classList).toContain('vp-trigger');
    expect(focusables[1].classList).toContain('rail-collapse-btn');
    const labels = focusables.slice(2).map(el => el.getAttribute('aria-label'));
    expect(labels).toEqual([
      'Matrix', 'Exposure', 'Intel', 'Detect', 'Coverage',
      'Dashboard', 'Reports', 'Library', 'Status', 'Keyboard shortcuts and help', 'Settings',
    ]);
  });
});
