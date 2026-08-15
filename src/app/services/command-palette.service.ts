// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

/**
 * Open/close state for the universal search palette. Replaces the palette's
 * former ride on FilterService.activePanel ('search') now that panels are
 * routed pages. P3 extends this into a full command palette.
 */
@Injectable({ providedIn: 'root' })
export class CommandPaletteService {
  private openSubject = new BehaviorSubject<boolean>(false);
  open$: Observable<boolean> = this.openSubject.asObservable();

  get isOpen(): boolean {
    return this.openSubject.value;
  }

  open(): void {
    this.openSubject.next(true);
  }

  close(): void {
    this.openSubject.next(false);
  }

  toggle(): void {
    this.openSubject.next(!this.openSubject.value);
  }
}
