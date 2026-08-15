// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, NgZone, inject } from '@angular/core';
import { CommandPaletteService } from './command-palette.service';
import { HelpOverlayService } from './help-overlay.service';
import { FilterService } from './filter.service';
import { PanelNavService } from './panel-nav.service';
import { MatrixControlService } from './matrix-control.service';

/**
 * The single global keyboard listener (D8). Rules, in order:
 *   1. Escape closes the topmost overlay (palette → help), else deselects
 *      the technique. The matrix grid handles its own Escape (cell focus,
 *      multi-select) before this listener sees the event.
 *   2. Modifier combos work even while an input has focus.
 *   3. Single-key shortcuts are ignored while typing.
 * The display list lives in models/shortcuts.ts — keep the two in sync.
 */
@Injectable({ providedIn: 'root' })
export class HotkeysService {
  private readonly palette = inject(CommandPaletteService);
  private readonly help = inject(HelpOverlayService);
  private readonly filterService = inject(FilterService);
  private readonly panelNav = inject(PanelNavService);
  private readonly matrixControl = inject(MatrixControlService);
  private readonly zone = inject(NgZone);

  private started = false;

  /** Called once from AppComponent.ngOnInit. */
  init(): void {
    if (this.started) return;
    this.started = true;
    document.addEventListener('keydown', (e) => this.zone.run(() => this.onKeydown(e)));
  }

  private onKeydown(event: KeyboardEvent): void {
    // 1) Escape chain — before the input guard so it also works from the
    // palette's own search field.
    if (event.key === 'Escape') {
      if (this.palette.isOpen) {
        this.palette.close();
        event.preventDefault();
        return;
      }
      if (this.help.isOpen) {
        this.help.close();
        event.preventDefault();
        return;
      }
      if (this.isTyping(event)) return; // let inputs keep their own Escape
      this.filterService.selectTechnique(null);
      event.preventDefault();
      return;
    }

    // 2) Modifier combos — valid even while typing.
    if (event.ctrlKey || event.metaKey) {
      if (event.shiftKey && event.key.toLowerCase() === 'f') {
        event.preventDefault();
        this.palette.toggle();
        return;
      }
      switch (event.key.toLowerCase()) {
        case 'k':
          event.preventDefault();
          this.palette.open();
          return;
        case 'f':
          event.preventDefault();
          this.focusTechniqueSearch();
          return;
        case 'e':
          event.preventDefault();
          this.matrixControl.expandAll();
          return;
      }
      return;
    }

    // 3) Single keys — ignored while typing.
    if (this.isTyping(event)) return;

    switch (event.key) {
      case '?':
        event.preventDefault();
        this.help.toggle();
        break;
      case 'm':
        event.preventDefault();
        this.panelNav.open('matrix');
        break;
      case 'd':
        event.preventDefault();
        this.panelNav.toggle('dashboard');
        break;
      case 't':
        event.preventDefault();
        this.panelNav.toggle('timeline');
        break;
      case 'w':
        event.preventDefault();
        this.panelNav.toggle('watchlist');
        break;
      case 'r':
        event.preventDefault();
        this.panelNav.toggle('risk-matrix');
        break;
      case 'c':
        event.preventDefault();
        this.filterService.clearAll();
        break;
    }
  }

  private isTyping(event: KeyboardEvent): boolean {
    const target = event.target as HTMLElement | null;
    if (!target) return false;
    return ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable;
  }

  private focusTechniqueSearch(): void {
    const input = document.querySelector<HTMLInputElement>('.technique-search .search-input');
    if (input) {
      input.focus();
      input.select();
    }
  }
}
