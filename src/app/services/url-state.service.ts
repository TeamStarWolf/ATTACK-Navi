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
    // The WRITER is only started afterwards — subscribing it immediately
    // caused a boot race: urlRelevantState$ (BehaviorSubject-backed) emits
    // once right away, and on a slow machine that write fired while the deep
    // link's lazy route was still loading. `router.url` was still '/', so the
    // write navigated to '/' and CANCELLED the in-flight deep-link
    // navigation, bouncing the user to the matrix via the wildcard route.
    // (Never reproduced locally — fast machines always won the race; CI's
    // 2-core runners always lost it.)
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
        this.startWriter();
      });
  }

  /** Writer: serialize filter state into query params on every change. */
  private startWriter(): void {
    this.filterService.urlRelevantState$.subscribe(() => {
      // Never write over an in-flight navigation (e.g. a user click on a
      // lazy route racing a filter debounce) — a cancelled navigation loses
      // the user's destination. Skipped writes self-heal: lastWritten stays
      // unset, so the next state emission re-serializes.
      if (this.router.getCurrentNavigation() !== null) return;
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
