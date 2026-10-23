// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The thin technique page, #/technique/:domain/:id (P2-18, E2.3-b; S15):
// resolves the id, switches domain when the link names another one (filters
// cleared, as the toolbar's domain picker does), selects the technique, shows
// an empty state for an unknown id, and is the one route where AppComponent
// does not render the drawer.
import { Component, input } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideLocationMocks } from '@angular/common/testing';
import { NavigationEnd, provideRouter, Router } from '@angular/router';
import { BehaviorSubject, filter, firstValueFrom, take } from 'rxjs';
import { TechniquePageComponent } from './technique-page.component';
import { TechniqueEvidenceCardComponent } from '../../components/technique-evidence-card/technique-evidence-card.component';
import type { Technique } from '../../models/technique';
import type { Domain } from '../../models/domain';
import { DataService, type AttackDomain } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { AttackIdResolverService } from '../../services/attack-id-resolver.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { HotkeysService } from '../../services/hotkeys.service';
import { ThemeService } from '../../services/theme.service';
import { AppComponent, isTechniquePageUrl } from '../../app.component';
import { parseFixtureDomain, resetBrowserState } from '../../testing/lens-harness';

@Component({ selector: 'app-technique-evidence-card', standalone: true, template: '<p class="stub-card">{{ technique().attackId }}</p>' })
class StubCardComponent {
  readonly technique = input.required<Technique>();
}

@Component({ standalone: true, template: '' })
class Blank {}

const tech = (attackId: string, name: string): Technique =>
  ({ id: `attack-pattern--${attackId}`, attackId, name, url: `https://attack.mitre.org/techniques/${attackId}`, tacticShortnames: ['impair-process-control'] }) as unknown as Technique;

const T1059 = tech('T1059.001', 'PowerShell');
const T0807 = tech('T0807', 'Command-Line Interface');
const ENTERPRISE = { name: 'Enterprise ATT&CK', attackVersion: '19.2', techniques: [T1059] } as unknown as Domain;
const ICS = { name: 'ICS ATT&CK', attackVersion: '19.2', techniques: [T0807] } as unknown as Domain;

describe('TechniquePageComponent (P2-18)', () => {
  let fixture: ComponentFixture<TechniquePageComponent>;
  let current: BehaviorSubject<AttackDomain>;
  let domain$: BehaviorSubject<Domain | null>;
  let selected: BehaviorSubject<Technique | null>;
  let clearAll: jasmine.Spy;
  let setHeatmapMode: jasmine.Spy;
  let switchDomain: jasmine.Spy;
  let open: jasmine.Spy;

  function render(domainParam: string, id: string, before?: () => void, heat?: string | readonly string[]): HTMLElement {
    current = new BehaviorSubject<AttackDomain>('enterprise');
    domain$ = new BehaviorSubject<Domain | null>(ENTERPRISE);
    selected = new BehaviorSubject<Technique | null>(null);
    clearAll = jasmine.createSpy('clearAll').and.callFake(() => selected.next(null));
    setHeatmapMode = jasmine.createSpy('setHeatmapMode');
    // DataService.switchDomain: the domain on screen changes now, its bundle loads later.
    switchDomain = jasmine.createSpy('switchDomain').and.callFake((d: AttackDomain) => { current.next(d); domain$.next(null); });
    open = jasmine.createSpy('open');
    TestBed.configureTestingModule({
      imports: [TechniquePageComponent],
      providers: [
        { provide: DataService, useValue: { domain$, currentDomain$: current, getCurrentAttackDomain: () => current.value, switchDomain } },
        { provide: FilterService, useValue: { selectedTechnique$: selected, selectTechnique: (t: Technique | null) => selected.next(t), clearAll, setHeatmapMode } },
        { provide: PanelNavService, useValue: { open } },
      ],
    });
    TestBed.overrideComponent(TechniquePageComponent, {
      remove: { imports: [TechniqueEvidenceCardComponent] },
      add: { imports: [StubCardComponent] },
    });
    before?.();
    fixture = TestBed.createComponent(TechniquePageComponent);
    fixture.componentRef.setInput('domain', domainParam);
    fixture.componentRef.setInput('id', id);
    if (heat !== undefined) fixture.componentRef.setInput('heat', heat);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('/technique/ics/T0807 switches to ICS (filters cleared first) and selects the technique', () => {
    const el = render('ics', 'T0807');
    expect(clearAll).toHaveBeenCalledTimes(1);
    expect(switchDomain).toHaveBeenCalledOnceWith('ics');
    expect(clearAll).toHaveBeenCalledBefore(switchDomain);
    expect(text(el)).toContain('Loading ICS ATT&CK');

    domain$.next(ICS);
    fixture.detectChanges();
    expect(selected.value).toBe(T0807);
    expect(text(el.querySelector('.tp-id'))).toBe('T0807');
    expect(text(el.querySelector('.tp-name'))).toBe('Command-Line Interface');
    expect(text(el.querySelector('.tp-domain'))).toBe('ICS ATT&CK 19.2');
    expect(text(el.querySelector('.stub-card'))).toBe('T0807');
    expect(switchDomain).toHaveBeenCalledTimes(1);
  });

  // RP-F item 4: clearAll resets the lens, so the pasted heat= is applied again after the switch.
  for (const [dom, id, heat] of [['ics', 'T0807', 'coverage'], ['ics', 'T0807', 'kev'], ['mobile', 'T1404', 'coverage'], ['ics', 'T0807', 'status']] as const) {
    it(`/technique/${dom}/${id}?heat=${heat} keeps its lens across the domain switch`, () => {
      render(dom, id, undefined, heat);
      expect(switchDomain).toHaveBeenCalledOnceWith(dom);
      expect(setHeatmapMode).toHaveBeenCalledOnceWith(heat);
      expect(clearAll).toHaveBeenCalledBefore(setHeatmapMode);
      expect(switchDomain).toHaveBeenCalledBefore(setHeatmapMode);
    });
  }

  // RP-F decision 30a: a repeated heat key binds as an array. The page read it with
  // isHeatmapMode, which is false for an array, so ICS and Mobile links fell back to the
  // default lens after clearAll (round 5, 6/6). It now reads it as the matrix does
  // (firstValidHeat): the first valid value, in link order, on every domain.
  for (const [dom, id, heat] of [
    ['ics', 'T0807', ['bogus', 'coverage']],
    ['ics', 'T0807', ['coverage', 'bogus']],
    ['mobile', 'T1404', ['bogus', 'coverage']],
    ['ics', 'T0807', ['', 'kev', 'coverage']],
  ] as const) {
    it(`/technique/${dom}/${id}?heat=${heat.join('&heat=')} applies the first valid value after the domain switch`, () => {
      render(dom, id, undefined, heat);
      expect(switchDomain).toHaveBeenCalledOnceWith(dom);
      expect(setHeatmapMode).toHaveBeenCalledOnceWith(heat.find(h => h === 'coverage' || h === 'kev') as string);
      expect(clearAll).toHaveBeenCalledBefore(setHeatmapMode);
      expect(switchDomain).toHaveBeenCalledBefore(setHeatmapMode);
    });
  }

  it('a repeated heat key with no valid value is not a lens choice: the default stays (RP-F decision 30a)', () => {
    render('ics', 'T0807', undefined, ['bogus', 'also-bogus']);
    expect(clearAll).toHaveBeenCalledTimes(1);
    expect(setHeatmapMode).not.toHaveBeenCalled();
  });

  it('an invalid or empty heat= is not re-applied: the default lens clearAll chose stays (RP-F item 1)', () => {
    render('ics', 'T0807', undefined, 'bogus');
    expect(clearAll).toHaveBeenCalledTimes(1);
    expect(setHeatmapMode).not.toHaveBeenCalled();
    TestBed.resetTestingModule();
    render('ics', 'T0807', undefined, '');
    expect(setHeatmapMode).not.toHaveBeenCalled();
  });

  it('a link to the domain on screen with heat= leaves the lens the URL reader applied', () => {
    render('enterprise', 'T1059.001', undefined, 'coverage');
    expect(clearAll).not.toHaveBeenCalled();
    expect(setHeatmapMode).not.toHaveBeenCalled();
  });

  it('a link to the domain on screen neither clears filters nor switches', () => {
    const el = render('enterprise', 't1059.001');
    expect(clearAll).not.toHaveBeenCalled();
    expect(switchDomain).not.toHaveBeenCalled();
    expect(selected.value).toBe(T1059);
    expect(text(el.querySelector('.tp-id'))).toBe('T1059.001');
  });

  it('resolves a retired id to the technique that replaced it', () => {
    const el = render('enterprise', 'T1086', () => TestBed.inject(AttackIdResolverService).setSupersededBy(new Map([['T1086', 'T1059.001']])));
    expect(selected.value).toBe(T1059);
    expect(text(el.querySelector('.tp-id'))).toBe('T1059.001');
  });

  it('an unknown id shows an empty state and selects nothing', () => {
    const el = render('enterprise', 'T9999');
    const empty = el.querySelector('[data-testid="technique-page-empty"]');
    expect(empty).not.toBeNull();
    expect(text(empty)).toContain('No technique T9999 in Enterprise ATT&CK.');
    expect(el.querySelector('.stub-card')).toBeNull();
    expect(selected.value).toBeNull();
  });

  it('an unknown domain or a malformed id shows the empty state', () => {
    let el = render('nowhere', 'T1059.001');
    expect(text(el.querySelector('[data-testid="technique-page-empty"]'))).toContain('No technique T1059.001 in any ATT&CK domain this app loads.');
    expect(switchDomain).not.toHaveBeenCalled();
    TestBed.resetTestingModule();
    el = render('enterprise', '<b>crafted</b>');
    expect(text(el.querySelector('[data-testid="technique-page-empty"]'))).toContain('No technique with that id in Enterprise ATT&CK.');
    expect(el.textContent).not.toContain('crafted');
  });

  it('a domain chosen in the toolbar afterwards is not switched back; the page offers to load the link\'s domain', () => {
    const el = render('ics', 'T0807');
    domain$.next(ICS);
    fixture.detectChanges();
    current.next('enterprise');
    domain$.next(ENTERPRISE);
    fixture.detectChanges();
    expect(switchDomain).toHaveBeenCalledTimes(1);
    expect(text(el)).toContain('This link is for ICS ATT&CK; another ATT&CK domain is on screen.');
    (Array.from(el.querySelectorAll('button')).find(b => text(b) === 'Load ICS ATT&CK') as HTMLButtonElement).click();
    expect(switchDomain).toHaveBeenCalledTimes(2);
  });

  it('Open in matrix navigates with keepTechniqueSelection', () => {
    const el = render('enterprise', 'T1059.001');
    (el.querySelector('[data-testid="open-in-matrix"]') as HTMLButtonElement).click();
    expect(open).toHaveBeenCalledOnceWith('matrix', { keepTechniqueSelection: true });
  });
});

describe('AppComponent on the technique page (P2-18, S15)', () => {
  it('isTechniquePageUrl matches #/technique/:domain/:id only', () => {
    expect(isTechniquePageUrl('/technique/enterprise/T1059.001')).toBeTrue();
    expect(isTechniquePageUrl('/technique/ics/T0807?heat=coverage&tech=T0807')).toBeTrue();
    expect(isTechniquePageUrl('/technique/enterprise')).toBeFalse();
    expect(isTechniquePageUrl('/matrix?tech=T1059.001')).toBeFalse();
    expect(isTechniquePageUrl('/exposure/graph')).toBeFalse();
  });

  it('the sidebar is not rendered on the technique route, and comes back on the matrix with the selection kept', async () => {
    await TestBed.configureTestingModule({
      imports: [AppComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([
          { path: 'matrix', component: Blank },
          { path: 'technique/:domain/:id', component: Blank },
        ]),
        provideLocationMocks(),
      ],
    }).compileComponents();
    resetBrowserState();
    const domain = parseFixtureDomain();
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    const technique = domain.techniques.find(t => t.attackId === 'T1078')!;
    // The shell's global listeners (document keydown, OS theme) outlive this
    // TestBed in the page; keep them out so no later spec sees them.
    spyOn(TestBed.inject(HotkeysService), 'init');
    spyOn(TestBed.inject(ThemeService), 'init');
    const router = TestBed.inject(Router);
    const filterService = TestBed.inject(FilterService);
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const nav = async (go: () => Promise<boolean>) => {
      const done = firstValueFrom(router.events.pipe(filter(e => e instanceof NavigationEnd), take(1)));
      await go();
      await done;
      fixture.detectChanges();
    };
    const sidebar = () => (fixture.nativeElement as HTMLElement).querySelector('app-sidebar');
    const selectedNow = (): Technique | null => {
      let now: Technique | null = null;
      filterService.selectedTechnique$.pipe(take(1)).subscribe(t => (now = t));
      return now as Technique | null;
    };

    await nav(() => router.navigateByUrl('/matrix'));
    expect(sidebar()).not.toBeNull();
    await nav(() => router.navigateByUrl('/technique/enterprise/T1078'));
    filterService.selectTechnique(technique);
    fixture.detectChanges();
    expect(sidebar()).withContext('no drawer on the technique page').toBeNull();

    // Open in matrix: the selection travels with the navigation and the drawer opens on it.
    await nav(() => router.navigate(['/matrix'], { state: { keepTechniqueSelection: true } }));
    expect(sidebar()).not.toBeNull();
    expect(selectedNow()).toBe(technique);
    expect((fixture.nativeElement as HTMLElement).querySelector('.sidebar.open .attack-id')?.textContent).toBe('T1078');

    // Arriving on the page never clears the selection: the page owns it.
    await nav(() => router.navigateByUrl('/technique/enterprise/T1078'));
    expect(selectedNow()).toBe(technique);
    expect(sidebar()).toBeNull();
    fixture.destroy();
    resetBrowserState();
  });
});
