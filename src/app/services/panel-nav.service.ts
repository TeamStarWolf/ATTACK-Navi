// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { routeForPanel } from '../app.routes-map';
import { ActivePanel, FilterService } from './filter.service';

/**
 * Single entry point for "open panel X" during and after the router
 * migration. Ids present in PANEL_ROUTE_MAP navigate (query params
 * preserved so matrix filters survive); ids not yet converted fall back
 * to the legacy ActivePanel overlay mechanism. Once every panel is
 * routed, the fallback (and FilterService.activePanel) is deleted.
 */
@Injectable({ providedIn: 'root' })
export class PanelNavService {
  private readonly router = inject(Router);
  private readonly filterService = inject(FilterService);

  isRouted(id: string): boolean {
    return routeForPanel(id) !== undefined;
  }

  open(id: string): void {
    const commands = routeForPanel(id);
    if (commands) {
      void this.router.navigate(commands, { queryParamsHandling: 'preserve' });
    } else {
      this.filterService.setActivePanel(id as Exclude<ActivePanel, null>);
    }
  }

  /**
   * Toggle semantics preserved from the overlay era: activating an already
   * active destination returns to the matrix.
   */
  toggle(id: string): void {
    const commands = routeForPanel(id);
    if (!commands) {
      this.filterService.togglePanel(id as Exclude<ActivePanel, null>);
      return;
    }
    const target = commands.join('/').replace(/\/{2,}/g, '/');
    const current = this.router.url.split('?')[0];
    if (current === target && target !== '/matrix') {
      void this.router.navigate(['/matrix'], { queryParamsHandling: 'preserve' });
    } else {
      void this.router.navigate(commands, { queryParamsHandling: 'preserve' });
    }
  }
}
