// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';

import { Subscription } from 'rxjs';
import { FilterService, HeatmapMode } from '../../services/filter.service';
import { SettingsService } from '../../services/settings.service';
import { AttackDomain, DataService } from '../../services/data.service';
import { SAFE_SEQ, SAFE_STATUS, SAFE_CONTROLS } from '../../models/safe-palette';
import { HEATMAP_MODES, HeatmapModeDef, LensAvailability, LensRampStop, heatmapModeDef, lensAvailability, lensRungBadge } from '../../models/heatmap-modes';
import { LensCardService } from '../../services/lens-card.service';
import { LoadedBundleInfo, domainLabel, lensSourceVintage } from '../../models/lens-sources';

/** The unified lens's colorblind-safe 6-stop viridis, mirroring technique-cell. */
const SAFE_UNIFIED = ['#440154', '#414487', '#2a788e', '#22a884', '#7ad151', '#fde725'];

/** Scale note shown after the stops, by ramp scale (none for categorical and threshold bands). */
const SCALE_NOTE: Partial<Record<HeatmapModeDef['ramp']['scale'], string>> = {
  relative: 'share of the highest score',
  absolute: 'fewer to more',
};

/**
 * Lens legend (product plan 4.7). Everything it shows comes from the
 * HEATMAP_MODES registry: the rung badge and the lens question, the colour
 * stops, the domain line (with the stated reason when the lens has no data
 * for the current domain), the source line with each source's vintage, what
 * zero means, and a 'What is this lens?' button that opens the lens's
 * definition card.
 */
@Component({
  selector: 'app-legend',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="legend" role="group" [attr.aria-label]="'Legend: ' + def.label">
      <div class="legend-row">
        <span class="rung-badge" [attr.data-rung]="def.rung">{{ rungBadge }}</span>
        <span class="legend-label">{{ def.label }}</span>
        <div class="legend-scale">
          @for (stop of stops; track stop.label) {
            <div class="legend-stop">
              <div class="swatch" [style.background]="stop.color"></div>
              <span class="stop-label">{{ stop.label }}</span>
            </div>
          }
          @if (scaleNote) {
            <span class="scale-arrow">{{ scaleNote }}</span>
          }
        </div>
      </div>
      <p class="legend-question">{{ def.question }}</p>
      @if (notInDomain) {
        <p class="legend-domain"><span class="swatch hatch" aria-hidden="true"></span>n/a for {{ domainName }} (no source data)</p>
        <p class="legend-na-reason">{{ availability.reason }}</p>
      }
      <p class="legend-sources"><span class="meta-key">Sources:</span> {{ sourceLine }}</p>
      <div class="legend-foot">
        <p class="legend-zero">{{ def.zeroMeaning }}</p>
        <button type="button" class="lens-help-btn" aria-haspopup="dialog"
                [attr.aria-label]="'What is the ' + def.label + ' lens?'"
                (click)="openDefinition($event)">What is this lens?</button>
      </div>
    </div>
  `,
  styleUrl: './legend.component.scss',
})
export class LegendComponent implements OnInit, OnDestroy {
  heatmapMode: HeatmapMode = 'unified';
  private domain: AttackDomain = 'enterprise';
  private attackVersion = '';
  private freshness: LoadedBundleInfo['freshness'] = null;

  get def(): HeatmapModeDef {
    return heatmapModeDef(this.heatmapMode) ?? HEATMAP_MODES[0];
  }

  get rungBadge(): string {
    return lensRungBadge(this.def);
  }

  get scaleNote(): string | undefined {
    return SCALE_NOTE[this.def.ramp.scale];
  }

  get availability(): LensAvailability {
    return lensAvailability(this.def, this.domain);
  }

  get notInDomain(): boolean {
    return !this.availability.available;
  }

  /** Open the '?' definition card for the active lens (E1.2). */
  openDefinition(event: Event): void {
    this.lensCards.open(this.heatmapMode, event.currentTarget);
  }

  get domainName(): string {
    return domainLabel(this.domain);
  }

  /** Each source with its vintage, joined in registry order. */
  get sourceLine(): string {
    const bundle: LoadedBundleInfo = { domain: this.domain, attackVersion: this.attackVersion, freshness: this.freshness };
    return this.def.sources.map((id) => lensSourceVintage(id, bundle)).join(' · ');
  }

  get stops(): readonly LensRampStop[] {
    const def = this.def;
    // Mitigations follows the heatmap colour theme (and returns the
    // colorblind-safe ramp itself), exactly as the cell renderer does.
    if (def.value === 'coverage') {
      const colors = this.settingsService.getCoverageColors();
      return def.ramp.stops.map((s, i) => ({ ...s, color: colors[Math.min(i, colors.length - 1)] ?? s.color }));
    }
    if (!this.settingsService.current.colorblindSafe) return def.ramp.stops;
    return this.toSafeStops(def);
  }

  /**
   * Mirror the cell renderer's colorblind-safe mode: sequential scales show
   * the viridis ramp (first stop = the mode's zero color), categorical
   * status/controls show Okabe-Ito.
   */
  private toSafeStops(def: HeatmapModeDef): readonly LensRampStop[] {
    const base = def.ramp.stops;
    if (def.value === 'status') {
      const order = ['none', 'not-started', 'in-progress', 'planned', 'implemented'];
      return base.map((s, i) => ({ ...s, color: SAFE_STATUS[order[i]] ?? s.color }));
    }
    if (def.value === 'controls') {
      const order = ['none', 'planned', 'covered'];
      return base.map((s, i) => ({ ...s, color: SAFE_CONTROLS[order[i]] ?? s.color }));
    }
    if (def.value === 'f3-origin') {
      // Okabe-Ito blue / reddish purple, mirroring the cell renderer.
      const safe = ['#0072b2', '#cc79a7'];
      return base.map((s, i) => ({ ...s, color: safe[i] ?? s.color }));
    }
    if (def.value === 'unified') {
      return base.map((s, i) => ({ ...s, color: SAFE_UNIFIED[Math.min(i, SAFE_UNIFIED.length - 1)] }));
    }
    // Relative and EPSS bands: keep the zero stop, map the rest onto the viridis ramp.
    const steps = base.length - 1;
    return base.map((s, i) => {
      if (i === 0) return s;
      const rampIdx = Math.min(SAFE_SEQ.length - 1, Math.round(((i - 1) / Math.max(1, steps - 1)) * (SAFE_SEQ.length - 1)));
      return { ...s, color: SAFE_SEQ[rampIdx] };
    });
  }

  private sub = new Subscription();

  constructor(
    private filterService: FilterService,
    private settingsService: SettingsService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
    private lensCards: LensCardService,
  ) {}

  ngOnInit(): void {
    this.sub.add(
      this.filterService.heatmapMode$.subscribe(mode => {
        this.heatmapMode = mode;
        this.cdr.markForCheck();
      }),
    );
    this.sub.add(
      this.settingsService.settings$.subscribe(() => this.cdr.markForCheck()),
    );
    this.sub.add(
      this.dataService.currentDomain$.subscribe(domain => {
        this.domain = domain;
        this.cdr.markForCheck();
      }),
    );
    this.sub.add(
      this.dataService.domain$.subscribe(domain => {
        this.attackVersion = domain?.attackVersion ?? '';
        this.cdr.markForCheck();
      }),
    );
    this.sub.add(
      this.dataService.freshness$.subscribe(freshness => {
        this.freshness = freshness;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
  }
}
