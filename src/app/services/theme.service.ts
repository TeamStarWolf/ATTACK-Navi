// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

/** The stored theme, 'light' or 'dark'. Written only when the user picks one. */
export const THEME_STORAGE_KEY = 'mitre-nav-theme';
/**
 * Marks the stored theme as the user's own choice. Before D13 every first visit
 * wrote 'light' to THEME_STORAGE_KEY on its own, so a stored 'light' without
 * this marker is that old default, not a choice, and the OS decides instead.
 */
export const THEME_EXPLICIT_KEY = 'mitre-nav-theme-explicit';

const DARK_QUERY = '(prefers-color-scheme: dark)';

/**
 * Light/dark theme state. Owns the body class and the persisted choice so
 * the toolbar button and the palette's "Toggle theme" command share one
 * implementation.
 *
 * Plan E1.5, decision D13: the theme follows the operating system until the
 * user picks one, and an explicit choice always wins. Following the OS writes
 * nothing to storage, so a later OS change is still followed.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private isLightSubject = new BehaviorSubject<boolean>(false);
  isLight$: Observable<boolean> = this.isLightSubject.asObservable();

  private media: MediaQueryList | null = null;
  private readonly onOsChange = (e: MediaQueryListEvent): void => this.apply(!e.matches);

  get isLight(): boolean {
    return this.isLightSubject.value;
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
      this.apply(choice === 'light');
      return;
    }
    this.followOs();
  }

  /** An explicit user choice: flips the theme, stores it and stops following the OS. */
  toggle(): void {
    this.stopFollowingOs();
    const light = !this.isLightSubject.value;
    this.apply(light);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, light ? 'light' : 'dark');
      localStorage.setItem(THEME_EXPLICIT_KEY, '1');
    } catch {
      /* storage unavailable */
    }
  }

  /**
   * The user's stored choice, or null when there is none. A legacy 'dark'
   * counts as a choice: since light became the default (v0.10) 'dark' could
   * only be stored by the toggle. A legacy 'light' counts only with the marker.
   */
  private storedChoice(): 'light' | 'dark' | null {
    try {
      const stored = localStorage.getItem(THEME_STORAGE_KEY);
      if (stored === 'dark') return 'dark';
      if (stored === 'light' && localStorage.getItem(THEME_EXPLICIT_KEY) === '1') return 'light';
    } catch {
      /* storage unavailable */
    }
    return null;
  }

  private followOs(): void {
    let media: MediaQueryList | null = null;
    try {
      media = typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : null;
    } catch {
      media = null;
    }
    // No media query support: light, the pre-D13 default.
    this.apply(media ? !media.matches : true);
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

  private apply(light: boolean): void {
    this.isLightSubject.next(light);
    document.body.classList.toggle('light-mode', light);
  }
}
