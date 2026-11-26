// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';

/**
 * The stored theme. 'light' and 'dark' are the two OS-matchable schemes;
 * 'teamstarwolf' is the TeamStarWolf ("Radar") brand theme — a dark-family
 * palette the OS can never prefer, so it is only ever an explicit choice.
 */
export type Theme = 'light' | 'dark' | 'teamstarwolf';

/** The order the toolbar button and the palette command cycle through. */
export const THEME_ORDER: readonly Theme[] = ['light', 'dark', 'teamstarwolf'];

/** The next theme in the cycle after `theme` (wraps around). */
export function nextTheme(theme: Theme): Theme {
  const i = THEME_ORDER.indexOf(theme);
  return THEME_ORDER[(i + 1) % THEME_ORDER.length];
}

/** The stored theme: 'light', 'dark' or 'teamstarwolf'. Written only on an explicit pick. */
export const THEME_STORAGE_KEY = 'mitre-nav-theme';
/**
 * Marks the stored theme as the user's own choice. Before D13 every first visit
 * wrote 'light' to THEME_STORAGE_KEY on its own, so a stored 'light' without
 * this marker is that old default, not a choice, and the OS decides instead.
 */
export const THEME_EXPLICIT_KEY = 'mitre-nav-theme-explicit';

/** The body class each theme carries. 'dark' is the bare :root default (no class). */
const THEME_CLASS: Record<Theme, string | null> = {
  light: 'light-mode',
  dark: null,
  teamstarwolf: 'teamstarwolf-mode',
};

const DARK_QUERY = '(prefers-color-scheme: dark)';

/**
 * Theme state. Owns the body theme class and the persisted choice so the
 * toolbar button and the palette's theme command share one implementation.
 *
 * Plan E1.5, decision D13: light/dark follow the operating system until the
 * user picks a theme, and an explicit choice always wins. Following the OS
 * writes nothing to storage, so a later OS change is still followed. The
 * TeamStarWolf theme is dark-family and OS-independent, so it is reached only
 * by an explicit pick and, once stored, wins like any other choice.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private themeSubject = new BehaviorSubject<Theme>('dark');
  /** The active theme. */
  theme$: Observable<Theme> = this.themeSubject.asObservable();
  /**
   * True for the light theme only. Kept for the cell/legend colourers, which
   * paint a binary light/dark palette: the TeamStarWolf theme is dark-family,
   * so it reports false here and paints with the dark palette.
   */
  isLight$: Observable<boolean> = this.theme$.pipe(map((t) => t === 'light'));

  private media: MediaQueryList | null = null;
  private readonly onOsChange = (e: MediaQueryListEvent): void => this.apply(e.matches ? 'dark' : 'light');

  get theme(): Theme {
    return this.themeSubject.value;
  }

  get isLight(): boolean {
    return this.themeSubject.value === 'light';
  }

  /** True while the theme comes from the OS rather than a stored user choice. */
  get followsOs(): boolean {
    return this.media !== null;
  }

  /**
   * Applies the theme. Called once at startup. A stored user choice wins;
   * otherwise the OS colour scheme decides and later OS changes are followed.
   */
  init(): void {
    const choice = this.storedChoice();
    if (choice) {
      this.stopFollowingOs();
      this.apply(choice);
      return;
    }
    this.followOs();
  }

  /** An explicit user choice: applies the theme, stores it and stops following the OS. */
  setTheme(theme: Theme): void {
    this.stopFollowingOs();
    this.apply(theme);
    this.persist(theme);
  }

  /** Advances to the next theme in the cycle as an explicit choice. */
  cycle(): void {
    this.setTheme(nextTheme(this.themeSubject.value));
  }

  /**
   * Explicit light/dark toggle (the pre-TeamStarWolf control). Kept for
   * callers that only ever flip the two OS schemes; anything not already
   * light becomes light, and light becomes dark.
   */
  toggle(): void {
    this.setTheme(this.themeSubject.value === 'light' ? 'dark' : 'light');
  }

  /**
   * The user's stored choice, or null when there is none.
   *
   * Migration: a legacy 'dark' counts as a choice because since light became
   * the default (v0.10) only the toggle could store 'dark'. A 'light' or
   * 'teamstarwolf' counts only with the explicit marker — a stored 'light'
   * without it is the pre-D13 automatic default, and 'teamstarwolf' is only
   * ever written together with the marker.
   */
  private storedChoice(): Theme | null {
    try {
      const stored = localStorage.getItem(THEME_STORAGE_KEY);
      if (stored === 'dark') return 'dark';
      const explicit = localStorage.getItem(THEME_EXPLICIT_KEY) === '1';
      if (explicit && (stored === 'light' || stored === 'teamstarwolf')) return stored;
    } catch {
      /* storage unavailable */
    }
    return null;
  }

  private persist(theme: Theme): void {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
      localStorage.setItem(THEME_EXPLICIT_KEY, '1');
    } catch {
      /* storage unavailable */
    }
  }

  private followOs(): void {
    let media: MediaQueryList | null = null;
    try {
      media = typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : null;
    } catch {
      media = null;
    }
    // No media query support: light, the pre-D13 default.
    this.apply(media ? (media.matches ? 'dark' : 'light') : 'light');
    if (media && typeof media.addEventListener === 'function') {
      this.stopFollowingOs();
      this.media = media;
      media.addEventListener('change', this.onOsChange);
    }
  }

  private stopFollowingOs(): void {
    this.media?.removeEventListener('change', this.onOsChange);
    this.media = null;
  }

  private apply(theme: Theme): void {
    this.themeSubject.next(theme);
    const body = document.body;
    for (const t of THEME_ORDER) {
      const cls = THEME_CLASS[t];
      if (cls) body.classList.toggle(cls, t === theme);
    }
  }
}
