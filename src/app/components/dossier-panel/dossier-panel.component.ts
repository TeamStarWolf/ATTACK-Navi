// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { Subscription } from 'rxjs';

import {
  CveDossier,
  DossierCountermeasure,
  DossierTechnique,
  DossierTier,
  TIER_BLURB,
  TIER_LABEL,
  TIER_ORDER,
} from '../../models/dossier';
import { CveService } from '../../services/cve.service';
import { DossierService } from '../../services/dossier.service';
import { EpssService } from '../../services/epss.service';
import {
  ACTION_MEANING,
  DEFAULT_ENVIRONMENT,
  SsvcEnvironment,
  SsvcService,
} from '../../services/ssvc.service';

/** SSVC coordinator outcomes to CSS classes. See actionClass. */
const ACTION_CLASS: Readonly<Record<string, string>> = {
  act: 'action-act',
  attend: 'action-attend',
  'track*': 'action-track-star',
  track: 'action-track',
};

interface TierGroup {
  tier: DossierTier;
  label: string;
  blurb: string;
  items: DossierTechnique[];
}

@Component({
  selector: 'app-dossier-panel',
  standalone: true,
  imports: [FormsModule, DecimalPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dossier-panel.component.html',
  styleUrl: './dossier-panel.component.scss',
})
export class DossierPanelComponent implements OnInit, OnDestroy {
  query = '';
  dossier: CveDossier | null = null;
  loading = false;
  searching = false;
  notice: string | null = null;

  env: SsvcEnvironment = { ...DEFAULT_ENVIRONMENT };
  actionMeaning = ACTION_MEANING;
  tierLabel = TIER_LABEL;

  private subs = new Subscription();

  constructor(
    private dossierService: DossierService,
    private cveService: CveService,
    private epssService: EpssService,
    private ssvc: SsvcService,
    private route: ActivatedRoute,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Exploitation and In KEV both hinge on KEV membership.
    this.cveService.loadKev();

    // ?cve=… lets the CVE panel hand off to this view.
    this.subs.add(
      this.route.queryParamMap.subscribe(params => {
        const cve = params.get('cve');
        if (cve && cve.toUpperCase() !== this.dossier?.cveId) {
          this.query = cve.toUpperCase();
          this.open(this.query);
        }
      }),
    );

    // A late KEV or SSVC load changes the verdict, so recompute rather than leave a
    // stale one on screen.
    this.subs.add(this.cveService.kevLoaded$.subscribe(() => this.refreshVerdict()));
    this.subs.add(this.ssvc.loaded$.subscribe(() => this.refreshVerdict()));
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ── actions ──────────────────────────────────────────────────────────────

  submit(): void {
    const id = this.query.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
      this.notice = 'Enter a CVE identifier, for example CVE-2021-44228.';
      this.cdr.markForCheck();
      return;
    }
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { cve: id },
      queryParamsHandling: 'merge',
    });
    this.open(id);
  }

  private open(id: string): void {
    this.notice = null;
    this.loading = true;
    this.cdr.markForCheck();

    this.subs.add(
      this.dossierService.load(id, this.env).subscribe(d => {
        this.dossier = d;
        this.loading = false;
        this.cdr.markForCheck();

        // The live path needs an NVD record; fetch it once, then rebuild.
        if (d.source === 'live' && !this.cveService.getCachedCve(id) && !this.searching) {
          this.fetchThenReload(id);
        }
        this.ensureEpss(id);
      }),
    );
  }

  /** Pull the CVE from NVD, then rebuild the dossier now that the record exists. */
  private fetchThenReload(id: string): void {
    this.searching = true;
    this.notice = `${id} was not loaded yet — fetching it from NVD…`;
    this.cdr.markForCheck();
    this.cveService.searchCves(id);

    const sub = this.cveService.nvdCache$.subscribe(cache => {
      if (!cache.has(id)) return;
      sub.unsubscribe();
      this.searching = false;
      this.notice = null;
      this.subs.add(
        this.dossierService.load(id, this.env).subscribe(d => {
          this.dossier = d;
          this.cdr.markForCheck();
        }),
      );
    });
    this.subs.add(sub);
  }

  private ensureEpss(id: string): void {
    if (this.epssService.getScore(id)) return;
    this.subs.add(
      this.epssService.fetchScores([id]).subscribe({
        next: () => this.refreshVerdict(),
        error: () => undefined,
      }),
    );
  }

  /** Recompute the SSVC verdict without refetching everything. */
  refreshVerdict(): void {
    if (!this.dossier) return;
    this.dossier = this.dossierService.reevaluate(this.dossier, this.env);
    const score = this.epssService.getScore(this.dossier.cveId);
    if (score) {
      this.dossier = {
        ...this.dossier,
        epss: score.epss,
        epssPercentile: score.percentile,
      };
    }
    this.cdr.markForCheck();
  }

  // ── display ──────────────────────────────────────────────────────────────

  get tierGroups(): TierGroup[] {
    const d = this.dossier;
    if (!d) return [];
    return TIER_ORDER.map(tier => ({
      tier,
      label: TIER_LABEL[tier],
      blurb: TIER_BLURB[tier],
      items: d.techniques.filter(t => t.tier === tier),
    })).filter(g => g.items.length > 0);
  }

  get countermeasuresByTactic(): { tactic: string; items: DossierCountermeasure[] }[] {
    const d = this.dossier;
    if (!d) return [];
    const order = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'];
    const buckets = new Map<string, DossierCountermeasure[]>();
    for (const cm of d.countermeasures) {
      const key = cm.tactic || 'Other';
      const bucket = buckets.get(key);
      if (bucket) {
        bucket.push(cm);
      } else {
        buckets.set(key, [cm]);
      }
    }
    return [...buckets.entries()]
      .sort((a, b) => {
        const ai = order.indexOf(a[0]);
        const bi = order.indexOf(b[0]);
        return (ai < 0 ? order.length : ai) - (bi < 0 ? order.length : bi);
      })
      .map(([tactic, items]) => ({ tactic, items }));
  }

  /**
   * CTID's analyst notes for a tier, grouped by note and attributed to the techniques
   * that carry it. Notes are per-technique and genuinely differ within a tier, so
   * showing one as if it described the whole group misattributes it.
   */
  tierComments(items: DossierTechnique[]): { comment: string; ids: string[] }[] {
    const byComment = new Map<string, string[]>();
    for (const t of items) {
      if (!t.comment) continue;
      const ids = byComment.get(t.comment);
      if (ids) {
        ids.push(t.id);
      } else {
        byComment.set(t.comment, [t.id]);
      }
    }
    return [...byComment.entries()].map(([comment, ids]) => ({ comment, ids }));
  }

  get retiredCount(): number {
    return this.dossier?.techniques.filter(t => t.supersedes).length ?? 0;
  }

  get ctidCount(): number {
    return this.dossier?.techniques.filter(t => t.tier !== 'weakness-class').length ?? 0;
  }

  /** See SsvcPanelComponent.actionClass — an explicit table, not string surgery. */
  actionClass(action: string | undefined): string {
    return ACTION_CLASS[(action || '').toLowerCase()] ?? 'action-none';
  }

  timelineClass(timeline: string | undefined): string {
    if (!timeline) return 'deadline-low';
    const days = this.ssvc.timelineDays(timeline);
    if (days <= 3) return 'deadline-critical';
    if (days <= 14) return 'deadline-high';
    if (days <= 60) return 'deadline-medium';
    return 'deadline-low';
  }

  techniqueTitle(t: DossierTechnique): string {
    const v = this.dossier?.attackVersion ? ` v${this.dossier.attackVersion}` : '';
    if (t.supersedes) {
      return `${t.id} ${t.name} — replaces ${t.supersedes}, which ATT&CK${v} retired`;
    }
    if (t.unresolved) {
      return `${t.id} is not present in ATT&CK${v} and ATT&CK names no replacement.`;
    }
    return `${t.id} ${t.name}`;
  }

  attackUrl(id: string): string {
    // ATT&CK ids carry at most one dot (T1562.001 -> T1562/001), so replacing the
    // first is the whole job here, not an incomplete pass over a repeating pattern.
    return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
  }

  trackTech = (_: number, t: DossierTechnique) => t.id;
  trackId = (_: number, x: { id: string }) => x.id;
}
