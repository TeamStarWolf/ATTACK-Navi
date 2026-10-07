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
import { Subscription, TimeoutError, timeout } from 'rxjs';

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
import { DataService } from '../../services/data.service';
import { DossierService } from '../../services/dossier.service';
import { dossierToJson, dossierToMarkdown } from '../../services/dossier-export';
import { EpssService } from '../../services/epss.service';
import { CisaSsvcService } from '../../services/cisa-ssvc.service';
import { F3FraudService } from '../../services/f3-fraud.service';
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

/** Upper bound on one NVD lookup; the public API is slow without a key but not this slow. */
const NVD_FETCH_TIMEOUT_MS = 20000;

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

  /** Transient "Copied" / "Downloaded" confirmation for the export buttons. */
  exportState: '' | 'md-copied' | 'json-copied' | 'md-saved' | 'json-saved' | 'copy-failed' = '';

  private subs = new Subscription();

  /**
   * The CVE the panel is currently showing or building. Every asynchronous result is
   * checked against it, so a slow response for an earlier CVE cannot land on top of a
   * later one.
   */
  private requested: string | null = null;
  // Per-request subscriptions. Each open() replaces (and cancels) the previous set
  // instead of accumulating them in `subs` until destroy.
  private loadSub?: Subscription;
  private fetchSub?: Subscription;
  private cisaSub?: Subscription;
  private epssSub?: Subscription;

  constructor(
    private dossierService: DossierService,
    private cveService: CveService,
    private epssService: EpssService,
    private ssvc: SsvcService,
    public cisaSsvc: CisaSsvcService,
    private f3: F3FraudService,
    private dataService: DataService,
    private route: ActivatedRoute,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Exploitation and In KEV both hinge on KEV membership.
    this.cveService.loadKev();
    // The F3 overlap bundle loads separately from the Enterprise domain.
    this.f3.ensureLoaded();

    // ?cve=… lets the CVE panel hand off to this view.
    this.subs.add(
      this.route.queryParamMap.subscribe(params => {
        const cve = params.get('cve');
        if (cve && cve.toUpperCase() !== this.requested) {
          this.query = cve.toUpperCase();
          this.open(this.query);
        }
      }),
    );

    // A late KEV or SSVC load changes the verdict, so recompute rather than leave a
    // stale one on screen. A failed KEV load also recomputes: that attaches the
    // "catalog unavailable" warning so the KEV flag on screen is not mistaken for CISA's.
    this.subs.add(this.cveService.kevLoaded$.subscribe(() => this.refreshVerdict()));
    this.subs.add(this.cveService.kevError$.subscribe(() => this.refreshVerdict()));
    this.subs.add(this.ssvc.loaded$.subscribe(() => this.refreshVerdict()));
    // F3 can land after assembly; fold its overlap in without refetching everything.
    this.subs.add(
      this.f3.loaded$.subscribe(loaded => {
        if (loaded && this.dossier) {
          this.dossier = this.dossierService.recomputeF3(this.dossier);
          this.cdr.markForCheck();
        }
      }),
    );
    // A deep link can open an asset dossier before the ATT&CK bundle finishes parsing,
    // which leaves the domain-derived sections (threat actors, and for a live dossier the
    // mitigations/CAPEC/etc.) empty. Re-derive them once the domain is available.
    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        if (domain && this.dossier) {
          this.dossier = this.dossierService.recomputeEnrichment(this.dossier);
          this.cdr.markForCheck();
        }
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
    this.cancelRequest();
  }

  private cancelRequest(): void {
    this.loadSub?.unsubscribe();
    this.fetchSub?.unsubscribe();
    this.cisaSub?.unsubscribe();
    this.epssSub?.unsubscribe();
    this.loadSub = this.fetchSub = this.cisaSub = this.epssSub = undefined;
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
    // A new request supersedes everything in flight for the previous one.
    this.cancelRequest();
    this.requested = id;
    this.searching = false;
    this.notice = null;
    this.exportState = '';
    this.loading = true;
    this.cdr.markForCheck();

    this.loadSub = this.dossierService.load(id, this.env).subscribe(d => {
      if (!this.isCurrent(id)) return;
      this.dossier = d;
      this.loading = false;
      this.cdr.markForCheck();

      // The live path needs an NVD record; fetch it once, then rebuild.
      if (d.source === 'live' && !this.cveService.getCachedCve(id)) {
        this.fetchThenReload(id);
      }
      this.ensureEpss(id);
      this.fetchCisa(id);
    });
  }

  /** True while `id` is still the CVE this panel is showing or building. */
  private isCurrent(id: string): boolean {
    return this.requested === id;
  }

  /**
   * Retrieve CISA's authoritative *published* SSVC decision (separate from the computed
   * calculator) and merge it onto the dossier. Guarded: on any failure the field stays
   * null and the view says CISA has not published one.
   */
  private fetchCisa(id: string): void {
    const cached = this.cisaSsvc.getSsvc(id);
    if (cached && this.dossier?.cveId === id) {
      this.dossier = { ...this.dossier, cisaSsvc: cached };
      this.cdr.markForCheck();
      return;
    }
    this.cisaSub?.unsubscribe();
    this.cisaSub = this.cisaSsvc.fetchSsvc(id).subscribe(assessment => {
      if (this.isCurrent(id) && this.dossier?.cveId === id) {
        this.dossier = { ...this.dossier, cisaSsvc: assessment };
        this.cdr.markForCheck();
      }
    });
  }

  /**
   * Pull the CVE from NVD, then rebuild the dossier now that the record exists.
   *
   * `searching` must clear on every outcome — success, "NVD has no such CVE", an HTTP
   * failure (403/429 without an API key is routine), or a hung request — or the panel
   * would never fetch again. A failure is told to the reader instead of being shown as
   * the generic "search it on the CVE tab first" warning.
   */
  private fetchThenReload(id: string): void {
    this.searching = true;
    this.notice = `${id} was not loaded yet — fetching it from NVD…`;
    this.cdr.markForCheck();

    this.fetchSub?.unsubscribe();
    this.fetchSub = this.cveService
      .fetchCve(id)
      .pipe(timeout(NVD_FETCH_TIMEOUT_MS))
      .subscribe({
        next: item => {
          this.searching = false;
          if (!this.isCurrent(id)) return;
          if (!item) {
            this.notice = `NVD has no record for ${id}, so the dossier is built from the data already loaded.`;
            this.cdr.markForCheck();
            return;
          }
          this.notice = null;
          this.loadSub?.unsubscribe();
          this.loadSub = this.dossierService.load(id, this.env).subscribe(d => {
            if (!this.isCurrent(id)) return;
            this.dossier = d;
            this.cdr.markForCheck();
            this.fetchCisa(id);
          });
        },
        error: err => {
          this.searching = false;
          if (!this.isCurrent(id)) return;
          const reason = err instanceof TimeoutError ? 'the request timed out' : (err?.message ?? 'network error');
          this.notice = `NVD lookup for ${id} failed (${reason}). The dossier is built from the data already loaded; try again later.`;
          this.cdr.markForCheck();
        },
      });
  }

  private ensureEpss(id: string): void {
    if (this.epssService.getScore(id)) return;
    this.epssSub?.unsubscribe();
    this.epssSub = this.epssService.fetchScores([id]).subscribe({
      next: () => {
        if (this.isCurrent(id)) this.refreshVerdict();
      },
      error: () => undefined,
    });
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

  /** True when the dossier has any ATT&CK group/software/campaign usage. */
  get hasThreatActors(): boolean {
    const a = this.dossier?.threatActors;
    return !!a && (a.groups.length > 0 || a.software.length > 0 || a.campaigns.length > 0);
  }

  // ── export ─────────────────────────────────────────────────────────────────

  private get markdown(): string {
    return this.dossier ? dossierToMarkdown(this.dossier) : '';
  }

  private get json(): string {
    return this.dossier ? dossierToJson(this.dossier) : '';
  }

  copyMarkdown(): void {
    this.copy(this.markdown, 'md-copied');
  }

  copyJson(): void {
    this.copy(this.json, 'json-copied');
  }

  downloadMarkdown(): void {
    if (!this.dossier) return;
    this.download(this.markdown, `${this.dossier.cveId}-dossier.md`, 'text/markdown');
    this.flash('md-saved');
  }

  downloadJson(): void {
    if (!this.dossier) return;
    this.download(this.json, `${this.dossier.cveId}-dossier.json`, 'application/json');
    this.flash('json-saved');
  }

  private copy(text: string, ok: typeof this.exportState): void {
    if (!text) return;
    const clip = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
    if (clip?.writeText) {
      clip.writeText(text).then(
        () => this.flash(ok),
        () => this.flash('copy-failed'),
      );
    } else {
      this.flash('copy-failed');
    }
  }

  private download(text: string, filename: string, type: string): void {
    try {
      const blob = new Blob([text], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      this.flash('copy-failed');
    }
  }

  private flash(state: typeof this.exportState): void {
    this.exportState = state;
    this.cdr.markForCheck();
    setTimeout(() => {
      this.exportState = '';
      this.cdr.markForCheck();
    }, 2200);
  }

  trackTech = (_: number, t: DossierTechnique) => t.id;
  trackId = (_: number, x: { id: string }) => x.id;
}
