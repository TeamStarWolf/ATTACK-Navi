import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';
import { NavRailComponent } from './nav-rail.component';
import { CveService } from '../../services/cve.service';

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
        { provide: CveService, useValue: mockCveService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(NavRailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render all nav group dividers', () => {
    const dividers = fixture.nativeElement.querySelectorAll('.nav-divider-label');
    const labels = Array.from(dividers)
      .map((el: any) => el.textContent.trim())
      .filter((t: string) => t.length > 0);
    expect(labels).toContain('Threats');
    expect(labels).toContain('Analysis');
    expect(labels).toContain('Coverage');
    expect(labels).toContain('Tools');
  });

  it('should emit panelToggle on nav item click', () => {
    spyOn(component.panelToggle, 'emit');
    const navBtn = fixture.nativeElement.querySelector('.nav-item');
    navBtn.click();
    expect(component.panelToggle.emit).toHaveBeenCalled();
  });

  it('should apply active class to the active panel', () => {
    fixture.componentRef.setInput('activePanel', 'dashboard');
    fixture.detectChanges();
    const activeBtn = fixture.nativeElement.querySelector('.nav-item.active');
    expect(activeBtn).toBeTruthy();
    expect(activeBtn.getAttribute('aria-label')).toBe('Dashboard');
  });

  it('should show KEV badge when newKevCount > 0', () => {
    newKevCount$.next(5);
    fixture.detectChanges();
    const badge = fixture.nativeElement.querySelector('.nav-badge');
    expect(badge).toBeTruthy();
    expect(badge.textContent).toContain('+5');
  });

  it('should not show KEV badge when newKevCount is 0', () => {
    newKevCount$.next(0);
    fixture.detectChanges();
    const badge = fixture.nativeElement.querySelector('.nav-badge');
    expect(badge).toBeFalsy();
  });

  it('should dismiss KEV badge when CVE nav item is clicked', () => {
    const cveService = TestBed.inject(CveService) as jasmine.SpyObj<CveService>;
    spyOn(component.panelToggle, 'emit');
    component.onNavClick('cve');
    expect(cveService.dismissKevBadge).toHaveBeenCalled();
    expect(component.panelToggle.emit).toHaveBeenCalledWith('cve');
  });

  it('should render nav items with icons and labels', () => {
    const navItems = fixture.nativeElement.querySelectorAll('.nav-list .nav-item');
    expect(navItems.length).toBeGreaterThan(10);
    const firstLabel = navItems[0].querySelector('.nav-label');
    expect(firstLabel.textContent.trim()).toBe('Dashboard');
  });
});
