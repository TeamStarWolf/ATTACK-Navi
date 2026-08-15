// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { NavigationEnd, Router } from '@angular/router';
import { filter, take } from 'rxjs';
import { FilterService } from './filter.service';

/**
 * Owns the URL <-> filter-state sync under the router.
 *
 * Filter state used to live in the raw location hash; it now lives in router
 * query params inside the hash URL (e.g. `#/matrix?heat=kev&grp=G0016`), so
 * share links keep working (via the legacy-hash shim in main.ts) and query
 * params survive workspace navigation (`queryParamsHandling: 'preserve'`).
 *
 * Reader: applies query params once, on the router's first NavigationEnd.
 * Writer: re-serializes on every (debounced) filter change with
 * `replaceUrl: true`, so filter edits never spam browser history. A
 * last-written guard prevents reader/writer feedback loops.
 */
@Injectable({ providedIn: 'root' })
export class UrlStateService {
  private readonly router = inject(Router);
  private readonly filterService = inject(FilterService);

  private lastWritten: string | null = null;
  private started = false;

  /** Called once from AppComponent.ngOnInit. */
  init(): void {
    if (this.started) return;
    this.started = true;

    // Reader: apply the initial URL's query params (deep links, legacy links).
    this.router.events
      .pipe(filter((e): e is NavigationEnd => e instanceof NavigationEnd), take(1))
      .subscribe(() => {
        const queryParams = this.router.parseUrl(this.router.url).queryParams;
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(queryParams)) {
          if (typeof value === 'string') params.set(key, value);
        }
        if ([...params.keys()].length) {
          this.filterService.applyUrlState(params);
        }
      });

    // Writer: serialize filter state into query params on every change.
    this.filterService.urlRelevantState$.subscribe(() => {
      const params = this.filterService.serializeUrlState();
      const serialized = new URLSearchParams(params).toString();
      if (serialized === this.lastWritten) return;
      this.lastWritten = serialized;
      const tree = this.router.parseUrl(this.router.url);
      tree.queryParams = params;
      void this.router.navigateByUrl(tree, { replaceUrl: true });
    });
  }

  /** Full current URL — the hash already carries route + filter state. */
  getShareUrl(): string {
    return window.location.href;
  }

  /** Clear all shareable filter state, keeping the current route path. */
  clearUrl(): void {
    const tree = this.router.parseUrl(this.router.url);
    tree.queryParams = {};
    this.lastWritten = '';
    void this.router.navigateByUrl(tree, { replaceUrl: true });
  }
}
