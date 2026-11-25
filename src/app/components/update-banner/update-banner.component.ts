// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { AppUpdateService } from '../../services/app-update.service';

/**
 * A small, non-intrusive prompt shown when a new app-shell version is ready, or when the worker
 * reports an unrecoverable state (see AppUpdateService). It never reloads under the user: they
 * choose when, so no in-session state is lost. "Reload" activates the new build and reloads;
 * "Later" dismisses it until the next event or load. (The alternative, a silent auto-reload on
 * VERSION_READY, is a one-line change in AppUpdateService and is the owner's call.)
 *
 * The role="status" live region is a real (fixed-position) wrapper that stays in the DOM, and only
 * its CONTENT appears when an update is ready, so a screen reader announces the change. It is a
 * fixed wrapper rather than `display: contents`, which some older browsers dropped from the
 * accessibility tree; `pointer-events` keep the empty region from covering the UI beneath it.
 */
@Component({
  selector: 'app-update-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="update-region" role="status" aria-live="polite">
      @if (update.updateReady()) {
        <div class="update-banner">
          <span class="update-banner__text">{{ message() }}</span>
          <span class="update-banner__actions">
            <button type="button" class="update-banner__reload" (click)="update.reloadToUpdate()">Reload</button>
            <button type="button" class="update-banner__dismiss" (click)="update.dismiss()">Later</button>
          </span>
        </div>
      }
    </div>
  `,
  styles: [
    `
      :host { display: contents; }
      // The live region is the fixed wrapper (in the a11y tree), empty and click-through until an
      // update is ready; the visual box inside takes pointer events.
      .update-region {
        position: fixed;
        inset-inline: 0;
        bottom: 16px;
        z-index: 1000;
        display: flex;
        justify-content: center;
        pointer-events: none;
      }
      .update-banner {
        pointer-events: auto;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 16px;
        width: fit-content;
        max-width: calc(100vw - 32px);
        padding: 10px 14px;
        background: var(--bg-elevated);
        color: var(--text-main);
        border: 1px solid var(--line-strong);
        border-radius: var(--radius-md);
        box-shadow: var(--shadow-md);
        font-size: var(--text-sm);
      }
      .update-banner__text { white-space: nowrap; }
      .update-banner__actions { display: inline-flex; gap: 8px; flex-shrink: 0; }
      .update-banner__reload,
      .update-banner__dismiss {
        padding: 5px 12px;
        border-radius: var(--radius-sm);
        font-size: var(--text-sm);
        cursor: pointer;
        border: 1px solid var(--line-strong);
        background: transparent;
        color: var(--text-main);
      }
      .update-banner__reload {
        border-color: var(--accent);
        background: var(--accent);
        // Dark text on the accent fill meets 4.5:1 in both themes (matches the primary button).
        color: var(--bg-base);
      }
      .update-banner__reload:hover { background: var(--accent-strong); border-color: var(--accent-strong); }
      .update-banner__dismiss:hover { background: var(--bg-hover); }
      :is(.update-banner__reload, .update-banner__dismiss):focus-visible {
        outline: 2px solid var(--accent);
        outline-offset: 2px;
      }
      // Below 769px the left nav becomes a fixed 56px bottom bar (with a floating control above
      // it): lift the prompt clear of both so they stay tappable, and give the buttons the 44px
      // touch target the rest of the small-screen UI uses.
      @media (max-width: 768px) {
        .update-region { bottom: calc(56px + 76px); }
        .update-banner__reload,
        .update-banner__dismiss { min-height: 44px; padding: 8px 14px; }
      }
      @media (prefers-reduced-motion: reduce) {
        .update-banner :is(button) { transition: none; }
      }
      @media (max-width: 480px) {
        .update-banner { flex-direction: column; gap: 8px; }
        .update-banner__text { white-space: normal; text-align: center; }
        .update-banner__actions { width: 100%; }
        .update-banner__actions > button { flex: 1 1 auto; }
      }
    `,
  ],
})
export class UpdateBannerComponent {
  readonly update = inject(AppUpdateService);

  /** The prompt text, by reason: a normal update vs the worker needing to recover. */
  readonly message = computed(() =>
    this.update.updateReason() === 'unrecoverable'
      ? 'ATT&CK-Navi ran into a problem. Reload to recover.'
      : 'A new version of ATT&CK-Navi is available.',
  );
}
