// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject, signal } from '@angular/core';
import { SwUpdate, VersionReadyEvent } from '@angular/service-worker';
import { filter } from 'rxjs/operators';

/** How often to ask the worker to look for a new version, for tabs left open for a long time. */
const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours

/**
 * Surfaces a ready app-shell update to the UI.
 *
 * The production build registers the Angular service worker (ngsw), which serves the cached
 * shell first and fetches a new release in the background; without this, a returning visitor
 * would keep seeing the previous build until some later load. This service listens for the
 * worker's VERSION_READY event and raises `updateReady`, so the shell can show a non-intrusive
 * "a new version is available" prompt.
 *
 * This change builds the PROMPT (it never reloads under the user, so it cannot lose their
 * in-session state). The alternative — a silent `activateUpdate()` + reload on VERSION_READY — is
 * a one-line change in the handler; WHICH BEHAVIOUR SHIPS IS THE OWNER'S CHOICE, not yet made.
 *
 * It also checks for a new version periodically (so a tab left open for days still learns of one)
 * and offers the same reload if the worker reports an unrecoverable state. `reloadToUpdate()`
 * activates the waiting worker and reloads, so the next paint is the new build.
 */
@Injectable({ providedIn: 'root' })
export class AppUpdateService {
  // Optional: provideServiceWorker supplies SwUpdate in the real app; left out of a test's
  // providers it is null, and this service is simply inert (so unrelated specs need not wire it).
  private readonly swUpdate = inject(SwUpdate, { optional: true });

  /** True once the prompt should show. */
  readonly updateReady = signal(false);
  /** Why the prompt shows: a new version is ready, or the worker hit an unrecoverable state (both
   *  resolve by reloading, but they warrant different wording). */
  readonly updateReason = signal<'ready' | 'unrecoverable'>('ready');

  constructor() {
    // Disabled in dev and wherever the service worker is not registered (SwUpdate.isEnabled is
    // false, or it was not provided), so this is inert outside the production build.
    if (!this.swUpdate?.isEnabled) return;

    this.swUpdate.versionUpdates
      .pipe(filter((e): e is VersionReadyEvent => e.type === 'VERSION_READY'))
      .subscribe(() => this.prompt('ready'));

    // An unrecoverable worker (e.g. a cache gone) is fixed the same way — reloading re-fetches a
    // clean, current shell — so offer the same reload, but say what actually happened.
    this.swUpdate.unrecoverable.subscribe(() => this.prompt('unrecoverable'));

    // A long-lived tab only learns of a new version on a load otherwise; poll for one.
    setInterval(() => void this.swUpdate?.checkForUpdate().catch(() => undefined), UPDATE_CHECK_INTERVAL_MS);
  }

  private prompt(reason: 'ready' | 'unrecoverable'): void {
    this.updateReason.set(reason);
    this.updateReady.set(true);
  }

  /** Activate the downloaded version and reload so the new build takes over. */
  async reloadToUpdate(): Promise<void> {
    // Reload even if activation fails (e.g. the worker went away): the reload still fetches the
    // newest shell, and this method must not reject.
    try {
      await this.swUpdate?.activateUpdate();
    } catch {
      /* fall through to reload */
    }
    this.reload();
  }

  /** The reload after activation: the new worker is in control, so this paints the new build.
   *  Isolated so a test can assert it without reloading the test runner. */
  protected reload(): void {
    document.location.reload();
  }

  /** Hide the prompt without updating; it returns on the next VERSION_READY (or next load). */
  dismiss(): void {
    this.updateReady.set(false);
  }
}
