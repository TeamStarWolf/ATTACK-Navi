// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

const STORAGE_KEY = 'mitre-nav-theme';

/**
 * Light/dark theme state. Owns the body class and the persisted choice so
 * the toolbar button and the palette's "Toggle theme" command share one
 * implementation.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private isLightSubject = new BehaviorSubject<boolean>(false);
  isLight$: Observable<boolean> = this.isLightSubject.asObservable();

  get isLight(): boolean {
    return this.isLightSubject.value;
  }

  /**
   * Applies the persisted theme. Called once at startup.
   * Clean Professional (v0.10): LIGHT is the default for new users; a stored
   * choice — either way — always wins.
   */
  init(): void {
    let stored: string | null = null;
    try {
      stored = localStorage.getItem(STORAGE_KEY);
    } catch {
      /* storage unavailable */
    }
    this.setLight(stored !== 'dark');
  }

  toggle(): void {
    this.setLight(!this.isLightSubject.value);
  }

  private setLight(light: boolean): void {
    this.isLightSubject.next(light);
    document.body.classList.toggle('light-mode', light);
    try {
      localStorage.setItem(STORAGE_KEY, light ? 'light' : 'dark');
    } catch {
      /* storage unavailable */
    }
  }
}
