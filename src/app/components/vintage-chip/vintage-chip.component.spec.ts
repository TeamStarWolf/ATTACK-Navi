// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { VintageChipComponent } from './vintage-chip.component';
import { SourceRegistryService } from '../../services/source-registry.service';
import { AttackDomain, DataService } from '../../services/data.service';

@Component({ selector: 'app-blank', standalone: true, template: '' })
class BlankComponent {}

describe('VintageChipComponent: the toolbar vintage chip (E1.4)', () => {
  let fixture: ComponentFixture<VintageChipComponent>;
  let registry: SourceRegistryService;
  let domain$: BehaviorSubject<{ attackVersion: string; attackModified: string } | null>;
  let freshness$: BehaviorSubject<'bundled' | 'cached' | 'live' | null>;
  let currentDomain$: BehaviorSubject<AttackDomain>;
  let pinned: string;

  const chip = (): HTMLAnchorElement => fixture.nativeElement.querySelector('[data-testid="vintage-chip"]');
  const text = (): string => chip().textContent!.replace(/\s+/g, ' ').trim();

  beforeEach(async () => {
    domain$ = new BehaviorSubject<{ attackVersion: string; attackModified: string } | null>(null);
    freshness$ = new BehaviorSubject<'bundled' | 'cached' | 'live' | null>(null);
    currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');
    pinned = '19.2';
    await TestBed.configureTestingModule({
      imports: [VintageChipComponent],
      providers: [
        provideRouter([{ path: 'status', component: BlankComponent }]),
        {
          provide: DataService,
          useValue: {
            domain$, freshness$, currentDomain$,
            getCurrentAttackDomain: () => currentDomain$.value,
            pinnedVersion: () => pinned,
          },
        },
      ],
    }).compileComponents();
    registry = TestBed.inject(SourceRegistryService);
    fixture = TestBed.createComponent(VintageChipComponent);
    fixture.detectChanges();
  });

  it('renders freshness$: the pinned ATT&CK version and the bundle date', () => {
    expect(chip().getAttribute('data-state')).toBe('loading');
    expect(text()).toContain('v19.2');

    domain$.next({ attackVersion: '19.2', attackModified: '2026-08-05T21:33:58.496Z' });
    freshness$.next('bundled');
    fixture.detectChanges();
    expect(chip().getAttribute('data-state')).toBe('pinned');
    expect(text()).toBe('ATT&CK v19.2 pinned 2026-08-05');
    expect(chip().querySelector('.attack-version')!.textContent).toBe('v19.2');
    expect(chip().getAttribute('aria-label')).toContain('ATT&CK 19.2 (pinned); bundle dated 2026-08-05');
    expect(chip().getAttribute('aria-label')).toContain('Open data health.');
  });

  it('opens the data-health view', async () => {
    expect(chip().getAttribute('href')).toBe('/status');
    const router = TestBed.inject(Router);
    await fixture.ngZone!.run(async () => { chip().click(); await fixture.whenStable(); });
    expect(router.url).toBe('/status');
  });

  it('says when a newer release is on screen for this session only, and names the pinned one', () => {
    domain$.next({ attackVersion: '20.0', attackModified: '2026-10-13T12:00:00.000Z' });
    freshness$.next('live');
    fixture.detectChanges();
    expect(chip().getAttribute('data-state')).toBe('session');
    expect(text()).toBe('ATT&CK v20.0 this session only 2026-10-13');
    expect(chip().getAttribute('aria-label')).toContain('the pinned release is 19.2');
  });

  it('names F3 by its own framework and says when the bundle states no date', () => {
    pinned = '1.2';
    currentDomain$.next('f3');
    domain$.next({ attackVersion: '1.2', attackModified: '' });
    freshness$.next('bundled');
    fixture.detectChanges();
    expect(text()).toBe('F3 v1.2 pinned undated');
    expect(chip().getAttribute('aria-label')).toContain('the bundle states no release date');
  });

  it('shows one aggregate source dot: failed beats stale beats ok', () => {
    const dot = () => chip().getAttribute('data-source-dot');
    const stale = registry.all().filter(r => r.status === 'stale').length;
    expect(dot()).toBe(stale ? 'stale' : 'ok');
    registry.fail('cisa-kev', 'network error');
    fixture.detectChanges();
    expect(dot()).toBe('failed');
    expect(chip().getAttribute('aria-label')).toContain('sources: 1 failed');
    registry.succeed('cisa-kev', 10);
    fixture.detectChanges();
    expect(dot()).toBe(stale ? 'stale' : 'ok');
  });
});
