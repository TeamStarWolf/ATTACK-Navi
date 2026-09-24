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
import { Subscription } from 'rxjs';
import { NvdCveItem } from '../../models/cve';
import { CveService } from '../../services/cve.service';
import { EpssService } from '../../services/epss.service';
import { AttackCveService, CveAttackMapping } from '../../services/attack-cve.service';
import {
  SsvcService,
  SsvcResult,
  SsvcEnvironment,
  SsvcPoint,
  ACTION_MEANING,
  DEFAULT_ENVIRONMENT,
} from '../../services/ssvc.service';

type OverrideKey = 'exploitation' | 'automatable' | 'impact' | 'inKev' | 'exposed' | 'mission';

/** SSVC coordinator outcomes to CSS classes. See actionClass. */
const ACTION_CLASS: Readonly<Record<string, string>> = {
  act: 'action-act',
  attend: 'action-attend',
  'track*': 'action-track-star',
  track: 'action-track',
};

interface WorklistRow {
  cve: NvdCveItem;
  result: SsvcResult;
  epss: number | null;
  /** CTID's per-CVE ATT&CK mapping, when it has one. */
  mapping: CveAttackMapping | null;
}

@Component({
  selector: 'app-ssvc-panel',
  standalone: true,
  imports: [FormsModule, DecimalPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ssvc-panel.component.html',
  styleUrl: './ssvc-panel.component.scss',
})
export class SsvcPanelComponent implements OnInit, OnDestroy {
  /** Environmental assumptions — the two inputs a CVE cannot supply. */
  env: SsvcEnvironment = { ...DEFAULT_ENVIRONMENT };

  query = '';
  loading = false;
  error: string | null = null;
  tablesLoaded = false;

  selected: NvdCveItem | null = null;
  selectedResult: SsvcResult | null = null;
  overrides: Partial<Record<OverrideKey, string>> = {};

  rows: WorklistRow[] = [];
  /** CVE the user asked to assess, held until its record arrives from NVD. */
  private pendingSelect: string | null = null;
  /** Shown when a requested CVE never arrives, so the button is not silently inert. */
  notFound: string | null = null;
  sortKey: 'deadline' | 'action' | 'epss' | 'cvss' | 'id' = 'deadline';

  actionMeaning = ACTION_MEANING;
  tableMeta: Record<string, unknown> = {};

  private subs = new Subscription();

  constructor(
    private cveService: CveService,
    private epssService: EpssService,
    private attackCve: AttackCveService,
    private ssvc: SsvcService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Exploitation and In KEV both hinge on KEV membership, so the catalogue must be
    // loaded before any outcome means anything.
    this.cveService.loadKev();

    this.subs.add(
      this.ssvc.loaded$.subscribe(loaded => {
        this.tablesLoaded = loaded && this.ssvc.available;
        this.tableMeta = this.ssvc.getMeta();
        this.recompute();
      }),
    );
    this.subs.add(this.cveService.kevLoaded$.subscribe(() => this.recompute()));
    this.subs.add(
      this.cveService.nvdCache$.subscribe(cache => {
        this.fetchEpssFor([...cache.keys()]);
        this.recompute();
      }),
    );
    this.subs.add(
      this.cveService.activeCve$.subscribe(cve => {
        if (cve) this.select(cve);
      }),
    );
    this.subs.add(
      this.cveService.searchResults$.subscribe(results => {
        // A pending id that the search did not return must be dropped, or it would sit
        // waiting and later latch onto an unrelated result.
        if (!this.pendingSelect) return;
        const wanted = this.pendingSelect;
        if (results.some(r => r.id.toUpperCase() === wanted)) return;
        if (results.length > 0 || !this.loading) {
          this.pendingSelect = null;
          this.notFound = `${wanted} was not returned by NVD. It may not exist yet, or ` +
            'the lookup failed.';
          this.cdr.markForCheck();
        }
      }),
    );
    this.subs.add(this.cveService.loading$.subscribe(v => {
      this.loading = v;
      this.cdr.markForCheck();
    }));
    this.subs.add(this.cveService.error$.subscribe(v => {
      this.error = v;
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  // ── actions ──────────────────────────────────────────────────────────────

  /**
   * Assess a CVE.
   *
   * Fetching it is only half the job: without selecting it, the detail below keeps
   * showing whatever was selected before, so the button appears to do nothing while
   * quietly loading a different CVE's verdict. A record already in the cache is
   * selected immediately; otherwise the id is held and picked up when NVD answers.
   */
  search(): void {
    const q = this.query.trim();
    if (!q) return;

    const id = q.toUpperCase();
    const isCveId = /^CVE-\d{4}-\d{4,}$/.test(id);
    this.pendingSelect = isCveId ? id : null;
    this.notFound = null;

    if (isCveId) {
      const cached = this.cveService.getCachedCve(id);
      if (cached) {
        this.select(cached);
        this.pendingSelect = null;
      }
    }
    this.cveService.searchCves(q);
  }

  select(cve: NvdCveItem): void {
    // Enrich at the point of selection. Worklist rows are already KEV-enriched, but
    // activeCve$ hands over the raw cached record, and a record parsed before the KEV
    // catalogue loaded carries isKev:false permanently. Evaluating that gives a weaker
    // verdict — track* instead of act — which then persists until some unrelated event
    // happens to trigger a recompute.
    this.selected = this.withLiveKev(cve);
    this.overrides = {};
    this.selectedResult = this.tablesLoaded
      ? this.ssvc.evaluate(this.selected, this.env)
      : null;
    this.cdr.markForCheck();
  }

  /** Re-evaluate the selected CVE after an override or environment change. */
  reevaluate(): void {
    if (this.selected && this.tablesLoaded) {
      this.selectedResult = this.ssvc.evaluate(this.selected, this.env, this.overrides);
    }
    this.recompute();
  }

  setOverride(key: OverrideKey, value: string): void {
    if (!value) {
      delete this.overrides[key];
    } else {
      this.overrides[key] = value;
    }
    this.reevaluate();
  }

  clearOverrides(): void {
    this.overrides = {};
    this.reevaluate();
  }

  hasOverrides(): boolean {
    return Object.keys(this.overrides).length > 0;
  }

  overrideFor(key: OverrideKey): string {
    return this.overrides[key] ?? '';
  }

  /** Map a point back to its override key, so the template can bind a control. */
  keyFor(point: SsvcPoint): OverrideKey | null {
    const c = point.column;
    if (c.startsWith('Exploitation')) return 'exploitation';
    if (c.startsWith('Automatable')) return 'automatable';
    if (c.startsWith('Technical Impact')) return 'impact';
    if (c.startsWith('In KEV')) return 'inKev';
    if (c.startsWith('Publicly Exposed')) return 'exposed';
    if (c.startsWith('Mission and Well-Being')) return 'mission';
    return null;
  }

  sortBy(key: typeof this.sortKey): void {
    this.sortKey = key;
    this.sortRows();
    this.cdr.markForCheck();
  }

  // ── worklist ─────────────────────────────────────────────────────────────

  /**
   * Builds the worklist from CVEs already in the app's NVD cache. SSVC needs a CVSS
   * vector, which only arrives with an NVD record, so this deliberately does not try to
   * evaluate the whole KEV catalogue — that would mean hundreds of NVD calls and would
   * silently produce provisional answers for most of them.
   */
  private recompute(): void {
    if (!this.tablesLoaded) {
      this.rows = [];
      this.cdr.markForCheck();
      return;
    }
    if (this.pendingSelect) {
      const arrived = this.cveService.getCachedCve(this.pendingSelect);
      if (arrived) {
        this.pendingSelect = null;
        this.select(arrived);
      }
    }

    const cves = this.cveService.getAllCachedCves().map(c => this.withLiveKev(c));
    this.rows = cves.map(cve => ({
      cve,
      result: this.ssvc.evaluate(cve, this.env),
      epss: this.epssService.getScore(cve.id)?.epss ?? cve.epssScore ?? null,
      mapping: this.attackCve.getMappingForCve(cve.id) ?? null,
    }));
    this.sortRows();

    if (this.selected) {
      this.selected = this.withLiveKev(this.selected);
      this.selectedResult = this.ssvc.evaluate(this.selected, this.env, this.overrides);
    }
    this.cdr.markForCheck();
  }

  /**
   * Refresh KEV fields from the catalogue at evaluation time.
   *
   * A cached NVD record is parsed once, and if it was parsed before the KEV catalogue
   * finished loading its `isKev` stays false forever. That silently downgrades the
   * outcome — Log4Shell resolves to `track*` instead of `act` — so KEV membership is
   * always read live rather than trusted from the cached record.
   */
  private withLiveKev(cve: NvdCveItem): NvdCveItem {
    const entry = this.cveService.getKevEntry(cve.id);
    if (!entry) {
      return cve.isKev ? { ...cve, isKev: false } : cve;
    }
    return {
      ...cve,
      isKev: true,
      kevDateAdded: entry.dateAdded,
      kevDueDate: entry.dueDate,
      kevVendorProject: entry.vendorProject,
      kevProduct: entry.product,
      kevKnownRansomware: entry.knownRansomwareCampaignUse?.toLowerCase() === 'known',
    };
  }

  /** EPSS is a display signal here, not an SSVC input; failures are non-fatal. */
  private fetchEpssFor(ids: string[]): void {
    const missing = ids.filter(id => !this.epssService.getScore(id));
    if (missing.length === 0) return;
    this.subs.add(
      this.epssService.fetchScores(missing).subscribe({
        next: () => this.recompute(),
        error: () => undefined,
      }),
    );
  }

  private sortRows(): void {
    const dir = (a: number, b: number) => a - b;
    this.rows.sort((x, y) => {
      switch (this.sortKey) {
        case 'deadline':
          return (
            dir(
              this.ssvc.timelineDays(x.result.timeline),
              this.ssvc.timelineDays(y.result.timeline),
            ) ||
            dir(this.ssvc.actionRank(x.result.action), this.ssvc.actionRank(y.result.action))
          );
        case 'action':
          return dir(
            this.ssvc.actionRank(x.result.action),
            this.ssvc.actionRank(y.result.action),
          );
        case 'epss':
          return (y.epss ?? -1) - (x.epss ?? -1);
        case 'cvss':
          return (y.cve.cvssScore ?? -1) - (x.cve.cvssScore ?? -1);
        default:
          return x.cve.id.localeCompare(y.cve.id);
      }
    });
  }

  // ── display helpers ──────────────────────────────────────────────────────

  /**
   * Map an outcome to its class. Built from an explicit table rather than by editing
   * the outcome string: "track*" is the only value needing translation, and deriving a
   * class name from arbitrary text can only ever produce something malformed if the
   * table upstream gains a value we do not know about.
   */
  actionClass(action: string): string {
    return ACTION_CLASS[(action || '').toLowerCase()] ?? 'action-none';
  }

  timelineClass(timeline: string): string {
    const days = this.ssvc.timelineDays(timeline);
    if (days <= 3) return 'deadline-critical';
    if (days <= 14) return 'deadline-high';
    if (days <= 60) return 'deadline-medium';
    return 'deadline-low';
  }

  pointClass(point: SsvcPoint): string {
    return 'kind-' + point.kind;
  }

  get metaSource(): string {
    return String(this.tableMeta['source'] ?? '');
  }

  get metaGenerated(): string {
    return String(this.tableMeta['generated'] ?? '');
  }

  get metaNote(): string {
    return String(this.tableMeta['note'] ?? '');
  }

  get provisionalCount(): number {
    return this.rows.filter(r => !r.cve.cvssVector).length;
  }

  trackRow = (_: number, row: WorklistRow) => row.cve.id;
  trackPoint = (_: number, point: SsvcPoint) => point.column;
}
