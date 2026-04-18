// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

/** Top-level workspace mode. */
export type ViewMode = 'workbench' | 'library';

const STORAGE_KEY = 'attacknavi.viewMode';
const DEFAULT_MODE: ViewMode = 'workbench';

/**
 * Tracks which top-level workspace is shown — the ATT&CK matrix workbench or the
 * Library index. Persists across reloads via localStorage.
 */
@Injectable({ providedIn: 'root' })
export class ViewModeService {
  private subject = new BehaviorSubject<ViewMode>(this.readPersisted());
  readonly viewMode$: Observable<ViewMode> = this.subject.asObservable();

  get current(): ViewMode {
    return this.subject.value;
  }

  set(mode: ViewMode): void {
    if (mode === this.subject.value) return;
    this.subject.next(mode);
    this.persist(mode);
  }

  toggle(): void {
    this.set(this.current === 'workbench' ? 'library' : 'workbench');
  }

  private readPersisted(): ViewMode {
    try {
      const v = localStorage.getItem(STORAGE_KEY);
      if (v === 'workbench' || v === 'library') return v;
    } catch {
      // localStorage unavailable (SSR / disabled)
    }
    return DEFAULT_MODE;
  }

  private persist(mode: ViewMode): void {
    try {
      localStorage.setItem(STORAGE_KEY, mode);
    } catch {
      // ignore
    }
  }
}
