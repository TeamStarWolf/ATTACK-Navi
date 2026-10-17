// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.2 PR 2: the '?' definition card. It states the lens's question, rung,
// formula, sources with vintage, the domains it has data for and what zero
// means; it is a modal dialog with a focus trap that Escape closes, returning
// focus to the control that opened it.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LensDefinitionCardComponent } from './lens-definition-card.component';
import { AttackDomain, DataService } from '../../services/data.service';
import { LensCardService } from '../../services/lens-card.service';
import { HEATMAP_MODES, heatmapModeDef, lensAvailability, lensRungBadge } from '../../models/heatmap-modes';
import { lensSourceVintage } from '../../models/lens-sources';

describe('LensDefinitionCardComponent', () => {
  let fixture: ComponentFixture<LensDefinitionCardComponent>;
  let cards: LensCardService;
  let currentDomain$: BehaviorSubject<AttackDomain>;
  let opener: HTMLButtonElement;

  const host = (): HTMLElement => fixture.nativeElement as HTMLElement;
  const dialog = (): HTMLElement | null => host().querySelector('[role="dialog"]');
  const text = (sel: string): string => (host().querySelector(sel)?.textContent ?? '').trim();
  const key = (target: Element, k: string, shiftKey = false): KeyboardEvent => {
    const ev = new KeyboardEvent('keydown', { key: k, shiftKey, bubbles: true, cancelable: true });
    target.dispatchEvent(ev);
    fixture.detectChanges();
    return ev;
  };

  beforeEach(async () => {
    currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');
    await TestBed.configureTestingModule({
      imports: [LensDefinitionCardComponent],
      providers: [
        {
          provide: DataService,
          useValue: {
            currentDomain$,
            domain$: new BehaviorSubject({ attackVersion: '19.2' }),
            freshness$: new BehaviorSubject<'bundled' | 'cached' | 'live' | null>('bundled'),
          },
        },
      ],
    }).compileComponents();
    cards = TestBed.inject(LensCardService);
    fixture = TestBed.createComponent(LensDefinitionCardComponent);
    document.body.appendChild(fixture.nativeElement);
    opener = document.createElement('button');
    opener.textContent = 'open';
    document.body.appendChild(opener);
    fixture.detectChanges();
  });

  afterEach(() => {
    cards.close();
    opener.remove();
    (fixture.nativeElement as HTMLElement).remove();
  });

  const openFor = (mode: Parameters<LensCardService['open']>[0]): void => {
    opener.focus();
    cards.open(mode, opener);
    fixture.detectChanges();
  };

  it('renders nothing until a lens is opened', () => {
    expect(dialog()).toBeNull();
  });

  it('describes every one of the 33 lenses: question, rung, formula, sources with vintage, domains, zero meaning', () => {
    for (const def of HEATMAP_MODES) {
      openFor(def.value);
      expect(text('#lens-card-title')).withContext(def.value).toBe(def.label);
      expect(text('#lens-card-question')).withContext(def.value).toBe(def.question);
      expect(text('.lens-card-head .rung-badge')).withContext(def.value).toBe(lensRungBadge(def));
      expect(text('.lens-card-rung')).withContext(def.value).toContain(lensRungBadge(def));
      expect(text('.lens-card-formula')).withContext(def.value).toBe(def.formula);
      expect(text('.lens-card-zero')).withContext(def.value).toBe(def.zeroMeaning);
      const sources = Array.from(host().querySelectorAll('.lens-card-sources li')).map((li) => li.textContent!.trim());
      const bundle = { domain: 'enterprise' as const, attackVersion: '19.2', freshness: 'bundled' as const };
      expect(sources).withContext(def.value).toEqual(def.sources.map((id) => lensSourceVintage(id, bundle)));
      expect(text('.lens-card-domains')).withContext(def.value).not.toBe('');
      expect(text('.lens-card-blank')).toBe('Blank means NOT KNOWN TO US, not safe.');
      cards.close();
      fixture.detectChanges();
    }
  });

  it('is a labelled modal dialog', () => {
    openFor('unified');
    const d = dialog()!;
    expect(d.getAttribute('aria-modal')).toBe('true');
    expect(d.getAttribute('aria-labelledby')).toBe('lens-card-title');
    expect(d.getAttribute('aria-describedby')).toBe('lens-card-question');
  });

  it('moves focus into the dialog on open', () => {
    openFor('kev');
    expect(document.activeElement).toBe(host().querySelector('.lens-card-close'));
  });

  it('traps Tab and Shift+Tab inside the dialog', () => {
    openFor('kev');
    const close = host().querySelector('.lens-card-close') as HTMLElement;
    // The close button is the only focusable control, so both directions wrap to it.
    const tab = key(close, 'Tab');
    expect(tab.defaultPrevented).toBeTrue();
    expect(document.activeElement).toBe(close);
    const back = key(close, 'Tab', true);
    expect(back.defaultPrevented).toBeTrue();
    expect(document.activeElement).toBe(close);
  });

  it('closes on Escape and returns focus to the opener', () => {
    openFor('sigma');
    const ev = key(host().querySelector('.lens-card-close')!, 'Escape');
    expect(ev.defaultPrevented).toBeTrue();
    expect(cards.openMode()).toBeNull();
    expect(dialog()).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it('closes from the close button and the backdrop', () => {
    openFor('sigma');
    (host().querySelector('.lens-card-close') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(dialog()).toBeNull();
    openFor('sigma');
    (host().querySelector('.lens-card-backdrop') as HTMLElement).click();
    fixture.detectChanges();
    expect(dialog()).toBeNull();
  });

  it('states why the lens is n/a in the current domain', () => {
    currentDomain$.next('ics');
    openFor('sigma');
    expect(text('.lens-card-na')).toBe(lensAvailability(heatmapModeDef('sigma')!, 'ics').reason!);
    cards.close();
    openFor('coverage');
    expect(host().querySelector('.lens-card-na')).toBeNull();
  });
});
