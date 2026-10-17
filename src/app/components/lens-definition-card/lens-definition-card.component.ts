// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  AfterViewChecked,
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  ViewChild,
  computed,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AttackDomain, DataService } from '../../services/data.service';
import { LensCardService } from '../../services/lens-card.service';
import {
  LENS_RUNG_MEANING,
  heatmapModeDef,
  lensAvailability,
  lensRungBadge,
} from '../../models/heatmap-modes';
import { LoadedBundleInfo, domainLabel, lensSourceVintage } from '../../models/lens-sources';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * The '?' definition card for one lens (plan E1.2, legend contract 4.7): the
 * question it answers, its rung, the formula, each source with its vintage,
 * the domains it has data for, and what zero means. A modal dialog: focus
 * moves into it on open, Tab and Shift+Tab stay inside it, Escape or the
 * backdrop closes it, and focus goes back to the control that opened it.
 */
@Component({
  selector: 'app-lens-definition-card',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (def(); as d) {
      <div class="lens-card-backdrop" (click)="close()"></div>
      <div #dialog class="lens-card" role="dialog" aria-modal="true"
           aria-labelledby="lens-card-title" aria-describedby="lens-card-question"
           (keydown)="onKeydown($event)">
        <header class="lens-card-head">
          <span class="rung-badge" [attr.data-rung]="d.rung">{{ rungBadge() }}</span>
          <h2 id="lens-card-title" class="lens-card-title">{{ d.label }}</h2>
          <button #closeBtn type="button" class="lens-card-close" (click)="close()" aria-label="Close lens definition">×</button>
        </header>
        <p id="lens-card-question" class="lens-card-question">{{ d.question }}</p>
        @if (availability(); as a) {
          @if (!a.available) {
            <p class="lens-card-na"><span class="hatch" aria-hidden="true"></span>{{ a.reason }}</p>
          }
        }
        <dl class="lens-card-facts">
          <dt>Rung</dt>
          <dd class="lens-card-rung">{{ rungBadge() }}: {{ rungMeaning() }}</dd>
          <dt>Formula</dt>
          <dd class="lens-card-formula">{{ d.formula }}</dd>
          <dt>Sources</dt>
          <dd>
            <ul class="lens-card-sources">
              @for (line of sourceLines(); track $index) {
                <li>{{ line }}</li>
              }
            </ul>
          </dd>
          <dt>Has data for</dt>
          <dd class="lens-card-domains">{{ domainsLine() }}</dd>
          <dt>Zero means</dt>
          <dd class="lens-card-zero">{{ d.zeroMeaning }}</dd>
        </dl>
        <p class="lens-card-blank">Blank means NOT KNOWN TO US, not safe.</p>
      </div>
    }
  `,
  styleUrl: './lens-definition-card.component.scss',
})
export class LensDefinitionCardComponent implements AfterViewChecked {
  private readonly cards = inject(LensCardService);
  private readonly dataService = inject(DataService);
  private readonly destroyRef = inject(DestroyRef);

  @ViewChild('dialog') private dialogRef?: ElementRef<HTMLElement>;
  @ViewChild('closeBtn') private closeBtnRef?: ElementRef<HTMLButtonElement>;

  private readonly domain = signal<AttackDomain>('enterprise');
  private readonly attackVersion = signal('');
  private readonly freshness = signal<LoadedBundleInfo['freshness']>(null);
  /** The mode focus was last moved in for, so focus moves in once per open. */
  private focusedFor: string | null = null;

  readonly def = computed(() => {
    const mode = this.cards.openMode();
    return mode ? heatmapModeDef(mode) ?? null : null;
  });
  readonly rungBadge = computed(() => {
    const d = this.def();
    return d ? lensRungBadge(d) : '';
  });
  readonly rungMeaning = computed(() => {
    const d = this.def();
    return d ? LENS_RUNG_MEANING[d.rung] : '';
  });
  readonly availability = computed(() => {
    const d = this.def();
    return d ? lensAvailability(d, this.domain()) : null;
  });
  readonly domainsLine = computed(() => (this.def()?.domains ?? []).map(domainLabel).join(', '));
  readonly sourceLines = computed(() => {
    const d = this.def();
    if (!d) return [];
    const bundle: LoadedBundleInfo = { domain: this.domain(), attackVersion: this.attackVersion(), freshness: this.freshness() };
    return d.sources.map((id) => lensSourceVintage(id, bundle));
  });

  constructor() {
    this.dataService.currentDomain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => this.domain.set(d));
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => this.attackVersion.set(d?.attackVersion ?? ''));
    this.dataService.freshness$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((f) => this.freshness.set(f));
  }

  ngAfterViewChecked(): void {
    const mode = this.cards.openMode();
    if (!mode) {
      this.focusedFor = null;
      return;
    }
    if (this.focusedFor === mode || !this.closeBtnRef) return;
    this.focusedFor = mode;
    this.closeBtnRef.nativeElement.focus();
  }

  close(): void {
    this.cards.close();
  }

  /** Escape closes; Tab and Shift+Tab wrap inside the dialog (focus trap). */
  onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      this.close();
      return;
    }
    if (event.key !== 'Tab' || !this.dialogRef) return;
    const root = this.dialogRef.nativeElement;
    const focusable = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (!focusable.length) {
      event.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    const outside = !root.contains(active);
    if (event.shiftKey && (active === first || outside)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || outside)) {
      event.preventDefault();
      first.focus();
    }
  }
}
