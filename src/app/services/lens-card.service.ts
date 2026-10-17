// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, signal } from '@angular/core';
import type { HeatmapMode } from './filter.service';

/**
 * Which lens definition card is open (E1.2). The legend's 'What is this
 * lens?' button, the lens picker's '?' buttons and the matrix page's n/a
 * banner open it; the one card instance on the matrix page renders it. The
 * opener is kept so focus can go back to it when the card closes.
 */
@Injectable({ providedIn: 'root' })
export class LensCardService {
  private readonly openModeSignal = signal<HeatmapMode | null>(null);
  readonly openMode = this.openModeSignal.asReadonly();
  private opener: HTMLElement | null = null;

  open(mode: HeatmapMode, opener?: EventTarget | null): void {
    this.opener = opener instanceof HTMLElement ? opener : null;
    this.openModeSignal.set(mode);
  }

  /** Close the card and return focus to whatever opened it, if it is still on the page. */
  close(): void {
    if (this.openModeSignal() === null) return;
    this.openModeSignal.set(null);
    const opener = this.opener;
    this.opener = null;
    if (opener?.isConnected) opener.focus();
  }
}
