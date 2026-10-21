// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { BriefingStripComponent } from './briefing-strip.component';
import { SourceRegistryService } from '../../services/source-registry.service';
import { AttackUpdateState, DataService } from '../../services/data.service';
import { BUNDLED_KEV_SNAPSHOT } from '../../services/source-inventory';
import { BRIEFING_ALL_CLEAR } from '../../models/briefing';

describe('BriefingStripComponent: failures are announced to a screen reader (E1.4)', () => {
  let fixture: ComponentFixture<BriefingStripComponent>;
  let registry: SourceRegistryService;
  let update$: BehaviorSubject<AttackUpdateState>;

  const region = (): HTMLElement => fixture.nativeElement.querySelector('[data-testid="briefing-live"]');
  const text = (): string => region().textContent!.trim();

  beforeEach(async () => {
    update$ = new BehaviorSubject<AttackUpdateState>({ status: 'idle' });
    await TestBed.configureTestingModule({
      imports: [BriefingStripComponent],
      providers: [provideRouter([]), { provide: DataService, useValue: { update$ } }],
    }).compileComponents();
    registry = TestBed.inject(SourceRegistryService);
    fixture = TestBed.createComponent(BriefingStripComponent);
    fixture.detectChanges();
  });

  it('is a polite, atomic live region that is in the DOM before anything fails', () => {
    expect(region()).toBeTruthy();
    expect(region().getAttribute('role')).toBe('status');
    expect(region().getAttribute('aria-live')).toBe('polite');
    expect(region().getAttribute('aria-atomic')).toBe('true');
    expect(text()).toBe(BRIEFING_ALL_CLEAR);
    expect(fixture.nativeElement.querySelector('a[href="/status"]')).toBeNull();
  });

  it('updates the region text when a source fails, so the failure is announced', () => {
    const before = text();
    registry.fail('nvd', 'HTTP 403 Forbidden');
    fixture.detectChanges();
    expect(text()).not.toBe(before);
    expect(text()).toContain('1 source failed');
    expect(text()).toContain(registry.get('nvd').name);
    // The same element is updated in place; a new region would not be announced.
    expect(fixture.nativeElement.querySelectorAll('[role="status"]').length).toBe(1);

    registry.fail('epss', 'network error (no response)');
    fixture.detectChanges();
    expect(text()).toContain('2 sources failed');
    expect(text()).toContain(registry.get('epss').name);
    expect(fixture.nativeElement.querySelector('a[href="/status"]')?.textContent).toContain('Data health');
  });

  it('announces a recovered source by dropping it from the line', () => {
    registry.fail('nvd', 'HTTP 403 Forbidden');
    fixture.detectChanges();
    expect(text()).toContain('1 source failed');
    registry.succeed('nvd', 12);
    fixture.detectChanges();
    expect(text()).toBe(BRIEFING_ALL_CLEAR);
  });

  it("says 'using snapshot of <date>' when the live KEV feed fails and the bundled snapshot stands in", () => {
    registry.fail('cisa-kev', 'network error (no response)');
    fixture.detectChanges();
    expect(text()).toContain('1 source failed');
    expect(text()).not.toContain('using snapshot of');

    registry.succeed('cisa-kev-snapshot', 1400);
    fixture.detectChanges();
    expect(text()).toContain(`${registry.get('cisa-kev').name}: using snapshot of ${BUNDLED_KEV_SNAPSHOT.date}.`);
  });

  it('says when a source came back empty', () => {
    registry.succeed('nvd', 0);
    fixture.detectChanges();
    expect(text()).toContain('1 source answered with no technique ids');
  });

  it('announces the pending ATT&CK update offer, and the release in use after applying it', () => {
    update$.next({ status: 'available', pinnedVersion: '19.2', liveVersion: '20.0' });
    fixture.detectChanges();
    expect(text()).toContain('ATT&CK 20.0 is available; this view stays on 19.2 (pinned)');

    update$.next({ status: 'applied', pinnedVersion: '19.2', liveVersion: '20.0' });
    fixture.detectChanges();
    expect(text()).toContain('Using ATT&CK 20.0 for this session only; the pinned release is 19.2.');

    update$.next({ status: 'idle' });
    fixture.detectChanges();
    expect(text()).toBe(BRIEFING_ALL_CLEAR);
  });
});
