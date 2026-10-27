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
import { Title } from '@angular/platform-browser';
import { BehaviorSubject, filter, firstValueFrom, take } from 'rxjs';
import { TechniqueFetchCoordinator } from '../../services/technique-fetch-coordinator.service';
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

@Component({ selector: 'app-technique-evidence-card', standalone: true, template: '<p class="stub-card" [attr.data-surface]="surface()">{{ technique().attackId }}</p>' })
class StubCardComponent {
  readonly technique = input.required<Technique>();
  readonly surface = input<'drawer' | 'page'>('drawer');
}

@Component({ standalone: true, template: '' })
class Blank {}

const tech = (attackId: string, name: string): Technique =>
  ({ id: `attack-pattern--${attackId}`, attackId, name, url: `https://attack.mitre.org/techniques/${attackId}`, tacticShortnames: ['impair-process-control'] }) as unknown as Technique;

const T1059 = tech('T1059.001', 'PowerShell');
const T0807 = tech('T0807', 'Command-Line Interface');
/** Under two tactics, listed out of matrix order: the header names them in matrix order. */
const T1037 = { ...tech('T1037', 'Boot or Logon Initialization Scripts'), tacticShortnames: ['privilege-escalation', 'persistence'] } as unknown as Technique;
const tactic = (shortname: string, attackId: string, name: string, order: number) => ({ id: `x-mitre-tactic--${attackId}`, shortname, attackId, name, order });
const ENTERPRISE = {
  name: 'Enterprise ATT&CK', attackVersion: '19.2', techniques: [T1059, T1037],
  tactics: [tactic('persistence', 'TA0003', 'Persistence', 5), tactic('privilege-escalation', 'TA0004', 'Privilege Escalation', 6)],
} as unknown as Domain;
const ICS = { name: 'ICS ATT&CK', attackVersion: '19.2', techniques: [T0807], tactics: [tactic('impair-process-control', 'TA0106', 'Impair Process Control', 9)] } as unknown as Domain;

describe('TechniquePageComponent (P2-18)', () => {
  let fixture: ComponentFixture<TechniquePageComponent>;
  let current: BehaviorSubject<AttackDomain>;
  let domain$: BehaviorSubject<Domain | null>;
  let selected: BehaviorSubject<Technique | null>;
  let clearAll: jasmine.Spy;
  let setHeatmapMode: jasmine.Spy;
  let switchDomain: jasmine.Spy;
  let open: jasmine.Spy;
  let prime: jasmine.Spy;

  function render(domainParam: string, id: string, before?: () => void, heat?: string | readonly string[]): HTMLElement {
    current = new BehaviorSubject<AttackDomain>('enterprise');
    domain$ = new BehaviorSubject<Domain | null>(ENTERPRISE);
    selected = new BehaviorSubject<Technique | null>(null);
    clearAll = jasmine.createSpy('clearAll').and.callFake(() => selected.next(null));
    setHeatmapMode = jasmine.createSpy('setHeatmapMode');
    // DataService.switchDomain: the domain on screen changes now, its bundle loads later.
    switchDomain = jasmine.createSpy('switchDomain').and.callFake((d: AttackDomain) => { current.next(d); domain$.next(null); });
    open = jasmine.createSpy('open');
    prime = jasmine.createSpy('prime');
    TestBed.configureTestingModule({
      imports: [TechniquePageComponent],
      providers: [
        provideRouter([]),
        { provide: DataService, useValue: { domain$, currentDomain$: current, getCurrentAttackDomain: () => current.value, switchDomain } },
        {
          provide: FilterService,
          useValue: {
            selectedTechnique$: selected, selectTechnique: (t: Technique | null) => selected.next(t), clearAll, setHeatmapMode,
            heatmapMode$: new BehaviorSubject('frequency'),
          },
        },
        { provide: PanelNavService, useValue: { open } },
        { provide: TechniqueFetchCoordinator, useValue: { prime } },
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

  // ─── Technique page design PR 1 (fix-first) ──────────────────────────────────

  it('primes the fetch coordinator once the technique resolves, and only then (D3FEND parity with the drawer)', () => {
    render('ics', 'T0807');
    expect(prime).withContext('nothing to prime while the domain loads').not.toHaveBeenCalled();
    domain$.next(ICS);
    fixture.detectChanges();
    expect(prime).toHaveBeenCalledOnceWith(T0807);
    fixture.detectChanges();
    expect(prime).toHaveBeenCalledTimes(1);
  });

  it('an unknown id primes nothing', () => {
    render('enterprise', 'T9999');
    expect(prime).not.toHaveBeenCalled();
  });

  it('the h1 is plain text (id and name, no link) and the ATT&CK page is an external action with noopener noreferrer', () => {
    const el = render('enterprise', 'T1037');
    const h1 = el.querySelector<HTMLElement>('h1#tp-h1')!;
    expect(text(h1)).toBe('T1037 Boot or Logon Initialization Scripts');
    expect(h1.querySelector('a')).withContext('the h1 holds no link').toBeNull();
    expect(h1.getAttribute('tabindex')).toBe('-1');
    const ext = el.querySelector<HTMLAnchorElement>('[data-testid="tp-attack-link"]')!;
    expect(ext.getAttribute('href')).toBe('https://attack.mitre.org/techniques/T1037');
    expect(ext.target).toBe('_blank');
    expect(ext.rel.split(/\s+/).sort()).toEqual(['noopener', 'noreferrer']);
    expect(text(ext)).toBe('View T1037 on ATT&CK ↗ (opens in a new tab)');
    expect(ext.querySelector('[aria-hidden="true"]')?.textContent?.trim()).toBe('↗');
  });

  it('tactics read by their ATT&CK names in matrix order, each a link to the matrix with dom, heat and tech', () => {
    const el = render('enterprise', 'T1037');
    const links = Array.from(el.querySelectorAll<HTMLAnchorElement>('[data-testid="tp-tactic"]'));
    expect(links.map(a => text(a))).toEqual(['TA0003 Persistence', 'TA0004 Privilege Escalation']);
    expect(text(el.querySelector('[data-testid="tp-tactics"]'))).toBe('Tactics: TA0003 Persistence, TA0004 Privilege Escalation');
    expect(text(el)).not.toContain('privilege-escalation');
    const href = new URL(links[0].getAttribute('href')!, 'http://x');
    expect(href.pathname).toBe('/matrix');
    expect(href.searchParams.get('dom')).toBe('enterprise');
    expect(href.searchParams.get('heat')).toBe('frequency');
    expect(href.searchParams.get('tech')).toBe('T1037');
    expect(links[0].getAttribute('aria-label')).toContain('TA0003 Persistence');
  });

  it('a tactic link opens the matrix with the selection kept, so its drawer opens on this technique', async () => {
    const el = render('enterprise', 'T1037');
    const router = TestBed.inject(Router);
    const nav = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    el.querySelector<HTMLAnchorElement>('[data-testid="tp-tactic"]')!.click();
    expect(nav).toHaveBeenCalledTimes(1);
    const [url, extras] = nav.calls.mostRecent().args as [unknown, { state?: Record<string, unknown> }];
    expect(router.serializeUrl(url as never)).toBe('/matrix?dom=enterprise&heat=frequency&tech=T1037');
    expect(extras.state).toEqual({ keepTechniqueSelection: true });
  });

  it('the document title names the technique: "T1037 Boot or Logon Initialization Scripts · ATT&CK-Navi"', () => {
    render('enterprise', 'T1037');
    expect(TestBed.inject(Title).getTitle()).toBe('T1037 Boot or Logon Initialization Scripts · ATT&CK-Navi');
  });

  it('focus moves to the h1 when the technique resolves, and again when the page moves to another technique', async () => {
    const el = render('enterprise', 'T1037');
    await fixture.whenStable();
    fixture.detectChanges();
    expect(document.activeElement).toBe(el.querySelector('#tp-h1'));
    (document.activeElement as HTMLElement).blur();
    // Angular reuses the component on a technique-to-technique navigation: the reset runs again.
    fixture.componentRef.setInput('id', 'T1059.001');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(text(el.querySelector('#tp-h1'))).toBe('T1059.001 PowerShell');
    expect(document.activeElement).toBe(el.querySelector('#tp-h1'));
    expect(TestBed.inject(Title).getTitle()).toBe('T1059.001 PowerShell · ATT&CK-Navi');
  });

  it('focus is not taken from a field elsewhere that holds it (the onboarding dialog, a search box)', async () => {
    const outside = document.createElement('input');
    document.body.appendChild(outside);
    try {
      outside.focus();
      const el = render('enterprise', 'T1037');
      await fixture.whenStable();
      fixture.detectChanges();
      expect(document.activeElement).toBe(outside);
      expect(el.querySelector('#tp-h1')).not.toBeNull();
    } finally {
      outside.remove();
    }
  });

  it('the evidence card sits under an Evidence h2, so the outline reads h1, h2, then the card\'s h3s', () => {
    const el = render('enterprise', 'T1037');
    const section = el.querySelector('section.tp-evidence')!;
    expect(text(section.querySelector('h2'))).toBe('Evidence');
    expect(section.getAttribute('aria-labelledby')).toBe('tp-evidence-h');
    expect(section.querySelector('.stub-card')).not.toBeNull();
    expect(el.querySelector('article')!.getAttribute('aria-labelledby')).toBe('tp-h1');
    expect(section.querySelector('.stub-card')!.getAttribute('data-surface')).withContext('the card is told it is on the page').toBe('page');
  });

  // Technique page design 4.9: one main landmark, holding the technique article.
  it('a main landmark holds the technique article, labelled by its h1', () => {
    const el = render('enterprise', 'T1037');
    expect(el.querySelectorAll('main, [role="main"]').length).toBe(1);
    const article = el.querySelector('main > article.technique-page')!;
    expect(article.getAttribute('aria-labelledby')).toBe('tp-h1');
    expect(article.querySelector('h1#tp-h1')).not.toBeNull();
  });

  it('an unknown technique keeps the main landmark around its empty state', () => {
    const el = render('enterprise', 'T9999');
    expect(el.querySelectorAll('main').length).toBe(1);
    expect(el.querySelector('main > article.technique-page [data-testid="technique-page-empty"] h1#tp-h1')).not.toBeNull();
  });
});

describe('TechniquePageComponent host (technique page design 4.2)', () => {
  it('the host is a flex item that takes the width, scrolls, and is the container the page queries', () => {
    TestBed.configureTestingModule({
      imports: [TechniquePageComponent],
      providers: [
        provideRouter([]),
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null), currentDomain$: new BehaviorSubject('enterprise'), getCurrentAttackDomain: () => 'enterprise', switchDomain: () => undefined } },
        { provide: FilterService, useValue: { selectedTechnique$: new BehaviorSubject(null), heatmapMode$: new BehaviorSubject('frequency'), selectTechnique: () => undefined } },
        { provide: TechniqueFetchCoordinator, useValue: { prime: () => undefined } },
      ],
    });
    // The workspace as app.component.scss lays it out: a flex row with overflow hidden.
    const workspace = document.createElement('div');
    workspace.style.cssText = 'display:flex;overflow:hidden;width:1500px;height:600px';
    document.body.appendChild(workspace);
    try {
      const fixture = TestBed.createComponent(TechniquePageComponent);
      fixture.componentRef.setInput('domain', 'enterprise');
      fixture.componentRef.setInput('id', 'T1037');
      fixture.detectChanges();
      const host = fixture.nativeElement as HTMLElement;
      workspace.appendChild(host);
      const css = getComputedStyle(host);
      expect(css.flexGrow).toBe('1');
      expect(css.minWidth).toBe('0px');
      expect(css.overflowY).toBe('auto');
      expect(css.containerType).toBe('inline-size');
      expect(css.containerName).toBe('tpage');
      expect(host.getBoundingClientRect().width).withContext('the page takes the workspace width').toBe(1500);
      fixture.destroy();
    } finally {
      workspace.remove();
    }
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
