// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DataService } from '../../services/data.service';
import { SourceRegistryService } from '../../services/source-registry.service';
import { briefingItems, briefingMessage } from '../../models/briefing';

/**
 * Briefing strip v1 (plan 6.4, epic E1.4): one status line on every route,
 * inside a polite live region that stays in the DOM, so a screen reader hears
 * each change. It says which sources failed or came back empty, which stand-in
 * snapshot is in use ('using snapshot of <date>'), and the ATT&CK update on
 * offer or in use for this session. Later phases add KEV additions, new proof
 * and expiring proof.
 */
@Component({
  selector: 'app-briefing-strip',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="briefing-strip" data-testid="briefing-strip" [attr.data-items]="items().length">
      <span class="bs-label" aria-hidden="true">Briefing</span>
      <p class="bs-text" role="status" aria-live="polite" aria-atomic="true" data-testid="briefing-live">{{ message() }}</p>
      @if (items().length) {
        <a class="bs-link" routerLink="/status">Data health</a>
      }
    </div>
  `,
  styles: [`
    :host { display: block; flex-shrink: 0; }
    .briefing-strip {
      display: flex;
      align-items: baseline;
      gap: var(--space-3);
      padding: 3px var(--space-3);
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-raised);
      color: var(--text-primary);
      font-size: var(--text-xs);
      line-height: 1.45;
      min-width: 0;
    }
    .bs-label {
      font-weight: 650;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-secondary);
      flex-shrink: 0;
    }
    .bs-text {
      flex: 1 1 auto;
      min-width: 0;
      margin: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .briefing-strip:hover .bs-text, .briefing-strip:focus-within .bs-text { white-space: normal; }
    .bs-link {
      color: var(--text-primary);
      text-decoration: underline;
      white-space: nowrap;
      flex-shrink: 0;
    }
  `],
})
export class BriefingStripComponent {
  private readonly data = inject(DataService);
  private readonly registry = inject(SourceRegistryService);

  private readonly records = toSignal(this.registry.records$, { initialValue: this.registry.all() });
  private readonly update = toSignal(this.data.update$, { initialValue: this.data.update$.value });

  readonly items = computed(() => briefingItems(this.records(), this.update()));
  readonly message = computed(() => briefingMessage(this.items()));
}
