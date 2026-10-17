// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DataService } from '../../services/data.service';
import { SourceRegistryService } from '../../services/source-registry.service';
import {
  aggregateSourceDot,
  sourceCounts,
  vintageDescription,
  vintageOf,
  vintageStateLabel,
} from '../../models/briefing';

/**
 * The toolbar vintage chip (plan 6.4, epic E1.4): the ATT&CK release on screen,
 * whether it is the pinned bundle (decision D2) or a release chosen for this
 * session, the bundle's own date, and one aggregate source dot. It renders
 * DataService.freshness$, which was computed and never shown. A click opens the
 * data-health view (#/status), where every source has a Retry.
 */
@Component({
  selector: 'app-vintage-chip',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <a class="vintage-chip" routerLink="/status" data-testid="vintage-chip"
       [attr.data-state]="vintage().state" [attr.data-source-dot]="dot()"
       [attr.aria-label]="description()" [title]="description()">
      <span [class]="'vc-dot dot-' + dotClass()" aria-hidden="true"></span>
      <span class="vc-framework">{{ vintage().framework }}</span>&ngsp;<span class="attack-version">v{{ vintage().version }}</span>&ngsp;<span
        class="vc-state" [class.vc-session]="vintage().state === 'session'">{{ stateLabel() }}</span>
      @if (vintage().state !== 'loading') {
        &ngsp;<span class="vc-date">{{ vintage().date || 'undated' }}</span>
      }
    </a>
  `,
  styles: [`
    :host { display: inline-flex; min-width: 0; }
    .vintage-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-full);
      background: var(--bg-raised);
      color: var(--text-primary);
      font-size: var(--text-xs);
      line-height: 1.4;
      white-space: nowrap;
      text-decoration: none;
      cursor: pointer;
    }
    .vintage-chip:hover { border-color: var(--text-secondary); }
    .vintage-chip:focus-visible { outline: 2px solid var(--info); outline-offset: 2px; }
    .vc-framework { font-weight: 650; }
    .attack-version { font-variant-numeric: tabular-nums; font-weight: 650; }
    .vc-state, .vc-date { color: var(--text-secondary); }
    .vc-state.vc-session { color: var(--warning); font-weight: 650; }
    .vc-date { font-variant-numeric: tabular-nums; }
    .vc-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      flex-shrink: 0;
      background: var(--text-secondary);
    }
    .dot-ok { background: var(--success); }
    .dot-stale { background: var(--warning); }
    .dot-failed { background: var(--danger); }
    .dot-na { background: transparent; border: 1px solid var(--text-secondary); }
  `],
})
export class VintageChipComponent {
  private readonly data = inject(DataService);
  private readonly registry = inject(SourceRegistryService);

  private readonly domain = toSignal(this.data.domain$, { initialValue: null });
  private readonly freshness = toSignal(this.data.freshness$, { initialValue: null });
  private readonly attackDomain = toSignal(this.data.currentDomain$, { initialValue: this.data.getCurrentAttackDomain() });
  private readonly records = toSignal(this.registry.records$, { initialValue: this.registry.all() });

  readonly vintage = computed(() => {
    // pinnedVersion() reads the SourceRegistry, so the record list is a dependency.
    this.records();
    const domain = this.attackDomain();
    return vintageOf(domain, this.domain(), this.freshness(), this.data.pinnedVersion(domain));
  });
  readonly dot = computed(() => aggregateSourceDot(this.records()));
  readonly dotClass = computed(() => (this.dot() === 'n/a' ? 'na' : this.dot()));
  readonly stateLabel = computed(() => vintageStateLabel(this.vintage().state));
  readonly description = computed(() => vintageDescription(this.vintage(), this.dot(), sourceCounts(this.records())));
}
