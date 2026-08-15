// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import {
  ActivatedRouteSnapshot,
  BaseRouteReuseStrategy,
  DetachedRouteHandle,
} from '@angular/router';

/**
 * Detaches (instead of destroying) routed components whose route declares
 * `data: { reuse: true }`, and reattaches them on return. Used for /matrix —
 * rebuilding the full technique grid on every visit would drop expansion
 * state, multi-select, and scroll position — and opt-in for wizard-style
 * panels that keep in-progress state in component fields.
 */
@Injectable({ providedIn: 'root' })
export class AppRouteReuseStrategy extends BaseRouteReuseStrategy {
  private readonly stored = new Map<string, DetachedRouteHandle>();

  override shouldDetach(route: ActivatedRouteSnapshot): boolean {
    return route.data['reuse'] === true;
  }

  override store(route: ActivatedRouteSnapshot, handle: DetachedRouteHandle | null): void {
    const key = this.key(route);
    if (handle) {
      this.stored.set(key, handle);
    } else {
      this.stored.delete(key);
    }
  }

  override shouldAttach(route: ActivatedRouteSnapshot): boolean {
    return route.data['reuse'] === true && this.stored.has(this.key(route));
  }

  override retrieve(route: ActivatedRouteSnapshot): DetachedRouteHandle | null {
    return this.stored.get(this.key(route)) ?? null;
  }

  private key(route: ActivatedRouteSnapshot): string {
    return route.pathFromRoot
      .map((r) => r.routeConfig?.path ?? '')
      .filter(Boolean)
      .join('/');
  }
}
