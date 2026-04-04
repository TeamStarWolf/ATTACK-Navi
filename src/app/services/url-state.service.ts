import { Injectable } from '@angular/core';
import { FilterService } from './filter.service';

/**
 * UrlStateService provides a clean API for sharing the current filter state as a URL.
 *
 * The core URL read/write logic lives in FilterService (which already syncs state
 * to/from window.location.hash on every filter change via debounced subscription).
 * This service wraps that behaviour and adds the clipboard/share surface.
 */
@Injectable({ providedIn: 'root' })
export class UrlStateService {
  constructor(private filterService: FilterService) {}

  /**
   * Restore state from the current URL hash.
   * FilterService already calls readUrlState() in its own constructor, so this is
   * a no-op at runtime.  It is kept here so AppComponent can call it explicitly
   * at ngOnInit (belt-and-suspenders, and for clarity in the call-site).
   */
  restoreFromUrl(): void {
    // FilterService handles this in its constructor via readUrlState().
    // Nothing additional is needed here.
  }

  /**
   * Trigger a URL sync on the next tick.  FilterService already debounce-syncs on
   * every observable change, so in practice callers don't need to call this directly.
   */
  syncToUrl(): void {
    // FilterService owns the authoritative sync loop.
    // This method exists as an explicit escape-hatch if needed.
  }

  /**
   * Return the full current URL (including whatever hash FilterService has written).
   */
  getShareUrl(): string {
    return window.location.href;
  }

  /**
   * Remove the URL hash entirely (clears all shareable state from the address bar).
   */
  clearUrl(): void {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }
}
