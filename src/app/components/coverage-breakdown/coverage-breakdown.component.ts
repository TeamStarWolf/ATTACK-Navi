// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Domain } from '../../models/domain';
import { EnrichmentService, EnrichmentTotals } from '../../services/enrichment.service';

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
 * Deliberately separates two numbers that a single "% coverage" headline used to
 * conflate: ENRICHED (a technique carries ≥1 cross-framework signal — analytical
 * completeness of the workbench) vs DEFENDED (it has a mitigation, detection,
 * control, or D3FEND countermeasure — the honest posture signal). A per-framework
 * grid then shows each contributor; a new framework is one more row, sourced from
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
export class CoverageBreakdownComponent implements OnChanges {
  @Input() domain!: Domain;

  total = 0;
  enrichedCount = 0;
  enrichedPct = 0;
  defendedCount = 0;
  defendedPct = 0;
  rows: CoverageRow[] = [];

  constructor(private enrichment: EnrichmentService) {}

  ngOnChanges(): void {
    this.recompute();
  }

  private pct(n: number, d: number): number {
    return d > 0 ? Math.round((n / d) * 100) : 0;
  }

  private recompute(): void {
    if (!this.domain) return;
    const parents = this.domain.techniques.filter((t) => !t.isSubtechnique);
    const t: EnrichmentTotals = this.enrichment.totals(parents, this.domain);
    this.total = t.total;
    this.enrichedCount = t.enriched;
    this.enrichedPct = this.pct(t.enriched, t.total);
    this.defendedCount = t.defended;
    this.defendedPct = this.pct(t.defended, t.total);
    // Order: defensive contributors first (they feed "Defended"), then
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
