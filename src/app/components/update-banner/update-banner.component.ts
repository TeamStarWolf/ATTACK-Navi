// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { AppUpdateService } from '../../services/app-update.service';

/**
 * A small, non-intrusive prompt shown when a new app-shell version is ready (see
 * AppUpdateService). It never reloads under the user: they choose when, so no in-session state
 * is lost. "Reload" activates the new build and reloads; "Later" dismisses it until the next
 * ready event or load. (The alternative behaviour, a silent auto-reload on VERSION_READY, is a
 * one-line change in AppUpdateService and is the owner's call.)
 */
@Component({
  selector: 'app-update-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (update.updateReady()) {
      <div class="update-banner" role="status" aria-live="polite">
        <span class="update-banner__text">A new version of ATT&amp;CK-Navi is available.</span>
        <span class="update-banner__actions">
          <button type="button" class="update-banner__reload" (click)="update.reloadToUpdate()">Reload</button>
          <button type="button" class="update-banner__dismiss" (click)="update.dismiss()">Later</button>
        </span>
      </div>
    }
  `,
  styles: [
    `
      :host { display: contents; }
      .update-banner {
        position: fixed;
        inset-inline: 0;
        bottom: 16px;
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 16px;
        width: fit-content;
        max-width: calc(100vw - 32px);
        margin-inline: auto;
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
        color: #fff;
      }
      .update-banner__reload:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
      .update-banner__dismiss:hover { background: var(--bg-hover); }
      :is(.update-banner__reload, .update-banner__dismiss):focus-visible {
        outline: 2px solid var(--accent);
        outline-offset: 2px;
      }
      @media (prefers-reduced-motion: reduce) {
        .update-banner :is(button) { transition: none; }
      }
      @media (max-width: 480px) {
        .update-banner { flex-direction: column; gap: 8px; }
        .update-banner__text { white-space: normal; text-align: center; }
      }
    `,
  ],
})
export class UpdateBannerComponent {
  readonly update = inject(AppUpdateService);
}
