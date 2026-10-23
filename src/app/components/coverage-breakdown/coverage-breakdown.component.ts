// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnChanges, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { CommonModule } from '@angular/common';
import { Domain } from '../../models/domain';
import { EnrichmentService, EnrichmentTotals } from '../../services/enrichment.service';
import { POSTURE_LINE_LABELS } from '../posture-card/posture-card.component';

interface CoverageRow {
  label: string;
  hint: string;
  count: number;
  pct: number;
  defensive: boolean;
}

/**
 * Multi-framework coverage readout for the Status workspace.
 *
 * Two Known-rung headlines: Known 'mapped' (≥1 defensive reference input:
 * mitigation, detection content, control mapping, D3FEND countermeasure or
 * Atomic test; the same EnrichmentService.mappedRollup count every summary
 * surface shows, P2-08) and "Has mapped countermeasure" (the same without
 * Atomic tests). Threat-intel and CVE links feed neither; P2-08 retired the
 * old "Enriched" headline, which counted them. A per-framework grid then shows
 * each contributor; a new framework is one more row, sourced from
 * EnrichmentService.totals() — no headline math to touch.
 */
@Component({
  selector: 'app-coverage-breakdown',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './coverage-breakdown.component.html',
  styleUrl: './coverage-breakdown.component.scss',
})
export class CoverageBreakdownComponent implements OnChanges, OnInit {
  @Input() domain!: Domain;

  /** 'Known: mapped', composed from the vocabulary module. */
  readonly knownLabel = POSTURE_LINE_LABELS.known;

  total = 0;
  mappedCount = 0;
  mappedPct = 0;
  defendedCount = 0;
  defendedPct = 0;
  rows: CoverageRow[] = [];

  private readonly cdr = inject(ChangeDetectorRef);
  private readonly destroyRef = inject(DestroyRef);

  constructor(private enrichment: EnrichmentService) {}

  ngOnChanges(): void {
    this.recompute();
  }

  ngOnInit(): void {
    // The CVE / KEV row reads the CTID mapping, which loads on demand (this view's first
    // read asks for it): count again once it has arrived.
    this.enrichment.cveMappingsLoaded$().pipe(takeUntilDestroyed(this.destroyRef)).subscribe(loaded => {
      if (!loaded) return;
      this.recompute();
      this.cdr.markForCheck();
    });
  }

  private pct(n: number, d: number): number {
    return d > 0 ? Math.round((n / d) * 100) : 0;
  }

  private recompute(): void {
    if (!this.domain) return;
    const parents = this.domain.techniques.filter((t) => !t.isSubtechnique);
    const t: EnrichmentTotals = this.enrichment.totals(parents, this.domain);
    this.total = t.total;
    // Known 'mapped' over parent techniques: the one rollup's Known number.
    const known = this.enrichment.mappedRollup(this.domain).overall;
    this.mappedCount = known.mapped;
    this.mappedPct = known.pct;
    this.defendedCount = t.defended;
    this.defendedPct = this.pct(t.defended, t.total);
    // Order: defensive contributors first (they feed "Has mapped countermeasure"), then
    // context/validation families (enrichment-only).
    this.rows = [
      { label: 'ATT&CK Mitigations', hint: 'M-series mitigations', count: t.mitigation, pct: this.pct(t.mitigation, t.total), defensive: true },
      { label: 'Detections', hint: 'Sigma + CAR analytics', count: t.detection, pct: this.pct(t.detection, t.total), defensive: true },
      { label: 'D3FEND', hint: 'defensive countermeasures', count: t.d3fend, pct: this.pct(t.d3fend, t.total), defensive: true },
      { label: 'Control Frameworks', hint: 'NIST 800-53 · CRI · CIS · CSA CCM · M365', count: t.control, pct: this.pct(t.control, t.total), defensive: true },
      { label: 'Atomic Red Team', hint: 'adversary-emulation tests', count: t.atomic, pct: this.pct(t.atomic, t.total), defensive: false },
      { label: 'Threat Intel', hint: 'groups · software · campaigns', count: t.threatIntel, pct: this.pct(t.threatIntel, t.total), defensive: false },
      { label: 'CVE / KEV', hint: 'known-exploited + NVD', count: t.cve, pct: this.pct(t.cve, t.total), defensive: false },
    ];
  }
}
