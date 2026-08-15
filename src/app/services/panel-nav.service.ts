// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { routeForPanel } from '../app.routes-map';
import { CommandPaletteService } from './command-palette.service';

/**
 * Single entry point for "open panel X". Panel ids resolve to routes via
 * PANEL_ROUTE_MAP (query params preserved so matrix filters survive);
 * 'search' opens the command palette overlay. Unknown ids are ignored.
 */
@Injectable({ providedIn: 'root' })
export class PanelNavService {
  private readonly router = inject(Router);
  private readonly palette = inject(CommandPaletteService);

  isRouted(id: string): boolean {
    return routeForPanel(id) !== undefined;
  }

  open(id: string): void {
    if (id === 'search') {
      this.palette.open();
      return;
    }
    const commands = routeForPanel(id);
    if (commands) {
      void this.router.navigate(commands, { queryParamsHandling: 'preserve' });
    }
  }

  /**
   * Toggle semantics preserved from the overlay era: activating an already
   * active destination returns to the matrix.
   */
  toggle(id: string): void {
    if (id === 'search') {
      this.palette.toggle();
      return;
    }
    const commands = routeForPanel(id);
    if (!commands) return;
    const target = commands.join('/').replace(/\/{2,}/g, '/');
    const current = this.router.url.split('?')[0];
    if (current === target && target !== '/matrix') {
      void this.router.navigate(['/matrix'], { queryParamsHandling: 'preserve' });
    } else {
      void this.router.navigate(commands, { queryParamsHandling: 'preserve' });
    }
  }
}
