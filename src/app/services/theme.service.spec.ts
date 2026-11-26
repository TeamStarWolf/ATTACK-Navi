// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { THEME_EXPLICIT_KEY, THEME_ORDER, THEME_STORAGE_KEY, ThemeService, nextTheme } from './theme.service';

/** A controllable stand-in for matchMedia('(prefers-color-scheme: dark)'). */
class FakeDarkQuery {
  private listeners: Array<(e: MediaQueryListEvent) => void> = [];
  constructor(public matches: boolean) {}
  readonly media = '(prefers-color-scheme: dark)';
  addEventListener(_type: string, fn: (e: MediaQueryListEvent) => void): void {
    this.listeners.push(fn);
  }
  removeEventListener(_type: string, fn: (e: MediaQueryListEvent) => void): void {
    this.listeners = this.listeners.filter((l) => l !== fn);
  }
  /** The OS switches scheme. */
  set(dark: boolean): void {
    this.matches = dark;
    for (const l of [...this.listeners]) l({ matches: dark } as MediaQueryListEvent);
  }
  get listenerCount(): number {
    return this.listeners.length;
  }
}

// Plan E1.5, decision D13: the theme follows the OS, and an explicit user choice wins.
describe('ThemeService (E1.5, D13: theme follows the OS)', () => {
  let service: ThemeService;
  let os: FakeDarkQuery;

  const clearStorage = () => {
    localStorage.removeItem(THEME_STORAGE_KEY);
    localStorage.removeItem(THEME_EXPLICIT_KEY);
  };
  const bodyIsLight = () => document.body.classList.contains('light-mode');
  const bodyIsTeamStarWolf = () => document.body.classList.contains('teamstarwolf-mode');

  function start(osDark: boolean): void {
    os = new FakeDarkQuery(osDark);
    spyOn(window, 'matchMedia').and.callFake(((q: string) => {
      expect(q).toBe('(prefers-color-scheme: dark)');
      return os as unknown as MediaQueryList;
    }) as typeof window.matchMedia);
    service = TestBed.inject(ThemeService);
    service.init();
  }

  let hadLight: boolean;
  beforeEach(() => {
    hadLight = bodyIsLight();
    clearStorage();
    TestBed.configureTestingModule({});
  });

  afterEach(() => {
    clearStorage();
    document.body.classList.remove('teamstarwolf-mode');
    document.body.classList.toggle('light-mode', hadLight);
  });

  describe('with no stored choice (a fresh profile)', () => {
    it('is dark when the OS prefers dark', () => {
      start(true);
      expect(service.isLight).toBeFalse();
      expect(bodyIsLight()).toBeFalse();
      expect(service.followsOs).toBeTrue();
    });

    it('is light when the OS prefers light', () => {
      start(false);
      expect(service.isLight).toBeTrue();
      expect(bodyIsLight()).toBeTrue();
    });

    it('writes nothing to storage, so the default is never mistaken for a choice', () => {
      start(true);
      expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
      expect(localStorage.getItem(THEME_EXPLICIT_KEY)).toBeNull();
    });

    it('follows a later OS change', () => {
      start(false);
      os.set(true);
      expect(service.isLight).toBeFalse();
      expect(bodyIsLight()).toBeFalse();
      os.set(false);
      expect(service.isLight).toBeTrue();
    });

    it("treats a stored 'light' without the marker as the old automatic default, not a choice", () => {
      // Before D13 every first visit stored 'light' on its own.
      localStorage.setItem(THEME_STORAGE_KEY, 'light');
      start(true);
      expect(service.isLight).toBeFalse();
      expect(service.followsOs).toBeTrue();
    });
  });

  describe('an explicit user choice wins', () => {
    it('toggle stores the choice with the marker and stops following the OS', () => {
      start(true);
      service.toggle();
      expect(service.isLight).toBeTrue();
      expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
      expect(localStorage.getItem(THEME_EXPLICIT_KEY)).toBe('1');
      expect(service.followsOs).toBeFalse();
      expect(os.listenerCount).toBe(0);
      os.set(true);
      expect(service.isLight).toBeTrue();
    });

    it("a stored explicit 'light' wins over a dark OS", () => {
      localStorage.setItem(THEME_STORAGE_KEY, 'light');
      localStorage.setItem(THEME_EXPLICIT_KEY, '1');
      start(true);
      expect(service.isLight).toBeTrue();
      expect(service.followsOs).toBeFalse();
    });

    it("a stored 'dark' wins over a light OS (since v0.10 only the toggle could store it)", () => {
      localStorage.setItem(THEME_STORAGE_KEY, 'dark');
      start(false);
      expect(service.isLight).toBeFalse();
      expect(bodyIsLight()).toBeFalse();
      expect(service.followsOs).toBeFalse();
    });

    it('toggling twice returns to the first theme and keeps it as a choice', () => {
      start(false);
      service.toggle();
      service.toggle();
      expect(service.isLight).toBeTrue();
      expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
      expect(localStorage.getItem(THEME_EXPLICIT_KEY)).toBe('1');
    });
  });

  // The TeamStarWolf brand theme: a third, dark-family, OS-independent option.
  describe('the TeamStarWolf theme (a named third option)', () => {
    it('setTheme stores it with the marker, carries its own body class and reports dark-family', () => {
      start(true);
      service.setTheme('teamstarwolf');
      expect(service.theme).toBe('teamstarwolf');
      expect(bodyIsTeamStarWolf()).toBeTrue();
      expect(bodyIsLight()).toBeFalse();
      // Dark-family: the cell/legend colourers paint the dark palette for it.
      expect(service.isLight).toBeFalse();
      expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('teamstarwolf');
      expect(localStorage.getItem(THEME_EXPLICIT_KEY)).toBe('1');
      expect(service.followsOs).toBeFalse();
    });

    it('is only ever an explicit choice — the OS never selects it, and an OS change is ignored once chosen', () => {
      start(false);
      service.setTheme('teamstarwolf');
      os.set(true);
      expect(service.theme).toBe('teamstarwolf');
      os.set(false);
      expect(service.theme).toBe('teamstarwolf');
    });

    it('a stored explicit teamstarwolf wins over the OS', () => {
      localStorage.setItem(THEME_STORAGE_KEY, 'teamstarwolf');
      localStorage.setItem(THEME_EXPLICIT_KEY, '1');
      start(true);
      expect(service.theme).toBe('teamstarwolf');
      expect(bodyIsTeamStarWolf()).toBeTrue();
      expect(service.followsOs).toBeFalse();
    });

    it('a stored teamstarwolf without the marker is not honoured (defensive) and the OS decides', () => {
      localStorage.setItem(THEME_STORAGE_KEY, 'teamstarwolf');
      start(true);
      expect(service.theme).toBe('dark');
      expect(service.followsOs).toBeTrue();
    });

    it('switching themes removes the previous theme class', () => {
      start(false);
      service.setTheme('light');
      expect(bodyIsLight()).toBeTrue();
      service.setTheme('teamstarwolf');
      expect(bodyIsLight()).toBeFalse();
      expect(bodyIsTeamStarWolf()).toBeTrue();
      service.setTheme('dark');
      expect(bodyIsLight()).toBeFalse();
      expect(bodyIsTeamStarWolf()).toBeFalse();
    });
  });

  describe('cycling through all three themes', () => {
    it('nextTheme follows the fixed order and wraps around', () => {
      expect(THEME_ORDER).toEqual(['light', 'dark', 'teamstarwolf']);
      expect(nextTheme('light')).toBe('dark');
      expect(nextTheme('dark')).toBe('teamstarwolf');
      expect(nextTheme('teamstarwolf')).toBe('light');
    });

    it('cycle advances Light -> Dark -> TeamStarWolf -> Light as explicit choices', () => {
      start(false); // OS light, no stored choice
      expect(service.theme).toBe('light');
      service.cycle();
      expect(service.theme).toBe('dark');
      service.cycle();
      expect(service.theme).toBe('teamstarwolf');
      service.cycle();
      expect(service.theme).toBe('light');
      expect(service.followsOs).toBeFalse();
      expect(localStorage.getItem(THEME_EXPLICIT_KEY)).toBe('1');
    });
  });
});
