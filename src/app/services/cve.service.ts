// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, Subscription, of, combineLatest, catchError, timeout } from 'rxjs';
import { map } from 'rxjs/operators';
import { NvdCveItem, KevEntry } from '../models/cve';
import { AttackCveService } from './attack-cve.service';
import { CapecService } from './capec.service';
import { retryWithBackoff } from '../utils/retry';


@Injectable({ providedIn: 'root' })
export class CveService {
  private readonly NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  // CISA's official GitHub mirror of the KEV catalog (updated with the feed).
  // raw.githubusercontent.com sends Access-Control-Allow-Origin: * â€” the
  // cisa.gov feed does not, so it is only a fallback (works via extensions/
  // proxies but is CORS-blocked in a plain browser context).
  private readonly KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
  private readonly KEV_FALLBACK_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  private searchSub?: Subscription;
  private kevLoading = false;

  private searchResultsSubject = new BehaviorSubject<NvdCveItem[]>([]);
  private activeCveSubject = new BehaviorSubject<NvdCveItem | null>(null);
  private loadingSubject = new BehaviorSubject<boolean>(false);
  private errorSubject = new BehaviorSubject<string | null>(null);
  private kevMapSubject = new BehaviorSubject<Map<string, KevEntry>>(new Map());
  private nvdCacheSubject = new BehaviorSubject<Map<string, NvdCveItem>>(new Map());
  private kevLoadedSubject = new BehaviorSubject<boolean>(false);
  // Map of attackId -> number of KEV CVEs mapped to it
  private kevTechScoresSubject = new BehaviorSubject<Map<string, number>>(new Map());

  searchResults$: Observable<NvdCveItem[]> = this.searchResultsSubject.asObservable();
  activeCve$: Observable<NvdCveItem | null> = this.activeCveSubject.asObservable();
  loading$: Observable<boolean> = this.loadingSubject.asObservable();
  error$: Observable<string | null> = this.errorSubject.asObservable();
  nvdCache$: Observable<Map<string, NvdCveItem>> = this.nvdCacheSubject.asObservable();
  kevLoaded$: Observable<boolean> = this.kevLoadedSubject.asObservable();
  kevTechScores$: Observable<Map<string, number>> = this.kevTechScoresSubject.asObservable();

  /** Emits the number of new KEV entries since the user last viewed CVE panel (0 = none). */
  newKevCount$ = new BehaviorSubject<number>(0);

  /** Emits true once KEV data AND the CTID ATT&CKâ†’CVE data are both loaded. */
  ctidKevReady$: Observable<boolean>;

  constructor(
    private http: HttpClient,
    private attackCveService: AttackCveService,
    private capecService: CapecService,
  ) {
    this.ctidKevReady$ = combineLatest([
      this.kevLoadedSubject,
      this.attackCveService.loaded$,
    ]).pipe(map(([kevLoaded, ctidLoaded]) => kevLoaded && ctidLoaded));

    this.attackCveService.loaded$.subscribe(loaded => {
      if (loaded && this.kevMapSubject.value.size > 0) {
        this.computeKevTechScores([...this.kevMapSubject.value.values()]);
      }
    });
  }

  loadKev(): void {
    if (this.kevLoadedSubject.value || this.kevLoading) return;
    this.kevLoading = true;
    // GitHub mirror first (CORS-safe), direct CISA feed as fallback.
    this.http.get<any>(this.KEV_URL).pipe(
      timeout(10000),
      catchError(() => this.http.get<any>(this.KEV_FALLBACK_URL).pipe(timeout(8000))),
      catchError(() => of({ vulnerabilities: [] }))
    ).subscribe((data: any) => {
      const vulns: KevEntry[] = data.vulnerabilities ?? [];
      const map = new Map<string, KevEntry>();
      for (const v of vulns) {
        map.set(v.cveID, v);
      }
      this.kevMapSubject.next(map);
      this.kevLoading = false;
      this.kevLoadedSubject.next(true);

      // Track new KEV entries for notification badge
      const currentCount = vulns.length;
      const previousCount = parseInt(localStorage.getItem('mitre-nav-last-kev-count') ?? '0', 10);
      if (previousCount > 0 && currentCount > previousCount) {
        this.newKevCount$.next(currentCount - previousCount);
      }
      localStorage.setItem('mitre-nav-last-kev-count', String(currentCount));

      this.computeKevTechScores(vulns);
    });
  }

  /**
   * Builds techniqueâ†’count scores from CTID direct CVEâ†’ATT&CK mappings for a list of KEV CVE IDs.
   * Returns a Map of techniqueAttackId â†’ number of KEV CVEs that map to it via CTID data.
   */
  /** Reset the new-KEV notification badge (called when user views the CVE panel). */
  dismissKevBadge(): void {
    this.newKevCount$.next(0);
  }

  getKevScoresFromCtid(kevCveIds: string[]): Map<string, Set<string>> {
    const scores = new Map<string, Set<string>>();
    for (const cveId of kevCveIds) {
      const mapping = this.attackCveService.getMappingForCve(cveId);
      if (!mapping) continue;
      const allTechs = [
        ...new Set([
          ...mapping.primaryImpact,
          ...mapping.secondaryImpact,
          ...mapping.exploitationTechnique,
        ]),
      ];
      for (const techId of allTechs) {
        this.addTechniqueCve(scores, techId, cveId);
      }
    }
    return scores;
  }

  private computeKevTechScores(vulns: KevEntry[]): void {
    const merged = new Map<string, Set<string>>();

    // CWE-based scores (indirect)
    for (const v of vulns) {
      const cwes = Array.isArray(v.cwes) ? v.cwes : (typeof v.cwes === 'string' && v.cwes ? v.cwes.split(',').map((c: string) => c.trim()).filter(Boolean) : []);
      const attackIds = this.mapCwesToAttackIds(cwes);
      for (const id of attackIds) {
        this.addTechniqueCve(merged, id, v.cveID);
      }
    }

    // CTID-based scores (direct) â€” only available if AttackCveService has loaded
    const kevCveIds = vulns.map(v => v.cveID);
    const ctidScores = this.getKevScoresFromCtid(kevCveIds);
    for (const [techId, cveIds] of ctidScores) {
      if (!merged.has(techId)) merged.set(techId, new Set<string>());
      for (const cveId of cveIds) {
        merged.get(techId)!.add(cveId);
      }
    }

    const counts = new Map<string, number>();
    for (const [techId, cveIds] of merged) {
      counts.set(techId, cveIds.size);
    }

    this.kevTechScoresSubject.next(counts);
  }

  private addTechniqueCve(map: Map<string, Set<string>>, techId: string, cveId: string): void {
    if (!techId) return;

    if (!map.has(techId)) map.set(techId, new Set<string>());
    map.get(techId)!.add(cveId);

    if (techId.includes('.')) {
      const parentId = techId.split('.')[0];
      if (!map.has(parentId)) map.set(parentId, new Set<string>());
      map.get(parentId)!.add(cveId);
    }
  }

  searchCves(query: string): void {
    if (!query.trim()) return;
    this.searchSub?.unsubscribe();
    this.loadingSubject.next(true);
    this.errorSubject.next(null);

    const isCveId = /^CVE-\d{4}-\d+$/i.test(query.trim());
    const params = isCveId
      ? `cveId=${encodeURIComponent(query.trim().toUpperCase())}`
      : `keywordSearch=${encodeURIComponent(query.trim())}&resultsPerPage=20`;

    this.searchSub = this.http.get<any>(`${this.NVD_API}?${params}`).pipe(
      catchError(err => {
        this.errorSubject.next('NVD API error: ' + (err.message ?? 'network error'));
        this.loadingSubject.next(false);
        return of(null);
      })
    ).subscribe((data: any) => {
      this.loadingSubject.next(false);
      if (!data) return;
      const items = (data.vulnerabilities ?? []).map((v: any) => this.parseNvdItem(v.cve));
      this.cacheNvdItems(items);
      this.searchResultsSubject.next(items);
    });
  }

  selectCve(cve: NvdCveItem | null): void {
    this.activeCveSubject.next(cve);
  }

  clearResults(): void {
    this.searchResultsSubject.next([]);
    this.activeCveSubject.next(null);
  }

  /** Return all normalized NVD CVE records that have been loaded into the local cache. */
  getAllCachedCves(): NvdCveItem[] {
    return [...this.nvdCacheSubject.value.values()];
  }

  /** Return a specific cached NVD CVE record when available. */
  getCachedCve(cveId: string): NvdCveItem | null {
    return this.nvdCacheSubject.value.get(cveId) ?? null;
  }

  /** Return cached NVD records for a specific set of CVE IDs. */
  getCachedCves(cveIds: string[]): NvdCveItem[] {
    return cveIds
      .map(id => this.nvdCacheSubject.value.get(id))
      .filter((item): item is NvdCveItem => !!item);
  }

  /**
   * Map CWE ids to ATT&CK technique ids via MITRE's own CWE→CAPEC→ATT&CK
   * chain (CAPEC STIX data). Returns [] until the CAPEC bundle has loaded,
   * and [] for CWEs with no published chain — no speculated mappings.
   * (Replaces a generated 733-entry static table whose entries were ~3.5%
   * confirmable against this chain.)
   */
  mapCwesToAttackIds(cwes: string[]): string[] {
    const attackIds = new Set<string>();
    for (const cwe of cwes) {
      for (const capec of this.capecService.getCapecForCwe(cwe)) {
        for (const id of capec.attackIds) attackIds.add(id);
      }
    }
    return [...attackIds].sort();
  }

  /** Reverse-lookup via the CAPEC chain: CWEs published as related to a technique. */
  getAttackToCweIds(attackId: string): string[] {
    if (!attackId) return [];
    const cwes = new Set<string>();
    for (const capec of this.capecService.getCapecForTechnique(attackId)) {
      for (const cwe of capec.cweIds) cwes.add(cwe);
    }
    return [...cwes].sort();
  }

  /** Fetch CVEs from NVD for all CWEs associated with a technique. Batches serially to respect rate limits.
   *  Uses the apiKey from settings if provided (via apiKey parameter). */
  fetchNvdCvesByAttackId(
    attackId: string,
    apiKey = '',
  ): Observable<{ items: NvdCveItem[]; cwesFetched: string[]; totalResults: number }> {
    const cwes = this.getAttackToCweIds(attackId);
    if (cwes.length === 0) {
      return of({ items: [], cwesFetched: [], totalResults: 0 });
    }
    // Limit to first 5 most specific CWEs to avoid overwhelming NVD
    const targetCwes = cwes.slice(0, 5);
    const headers: Record<string, string> = apiKey ? { 'apiKey': apiKey } : {};

    // Serial requests to avoid rate limiting
    return new Observable(observer => {
      const allItems = new Map<string, NvdCveItem>();
      let idx = 0;
      const fetchNext = () => {
        if (idx >= targetCwes.length) {
          observer.next({ items: [...allItems.values()], cwesFetched: targetCwes, totalResults: allItems.size });
          observer.complete();
          return;
        }
        const cwe = targetCwes[idx++];
        // NVD CWE ID format is just "CWE-78" or the number part
        const cweParam = cwe.startsWith('CWE-') ? cwe : `CWE-${cwe}`;
        const url = `${this.NVD_API}?cweId=${encodeURIComponent(cweParam)}&resultsPerPage=100`;
        this.http.get<any>(url, { headers }).pipe(
          catchError(() => of({ vulnerabilities: [] }))
        ).subscribe(data => {
          const items = (data?.vulnerabilities ?? []).map((v: any) => this.parseNvdItem(v.cve));
          this.cacheNvdItems(items);
          for (const item of items) {
            if (!allItems.has(item.id)) allItems.set(item.id, item);
          }
          // Delay 300ms between requests to stay under NVD rate limit
          setTimeout(fetchNext, apiKey ? 100 : 300);
        });
      };
      fetchNext();
    });
  }

  isKev(cveId: string): boolean {
    return this.kevMapSubject.value.has(cveId);
  }

  getKevEntry(cveId: string): KevEntry | undefined {
    return this.kevMapSubject.value.get(cveId);
  }

  /** Return all KEV entries as a flat array. */
  getAllKevEntries(): KevEntry[] {
    return [...this.kevMapSubject.value.values()];
  }

  /** Group KEV entries by vendor/project. */
  getKevByVendor(): Map<string, KevEntry[]> {
    const byVendor = new Map<string, KevEntry[]>();
    for (const entry of this.kevMapSubject.value.values()) {
      const vendor = entry.vendorProject || 'Unknown';
      if (!byVendor.has(vendor)) byVendor.set(vendor, []);
      byVendor.get(vendor)!.push(entry);
    }
    return byVendor;
  }

  /** Return KEV entries aggregated by month (dateAdded). */
  getKevTimeline(): { month: string; count: number }[] {
    const byMonth = new Map<string, number>();
    for (const entry of this.kevMapSubject.value.values()) {
      const month = entry.dateAdded?.substring(0, 7) || 'unknown';
      byMonth.set(month, (byMonth.get(month) ?? 0) + 1);
    }
    return [...byMonth.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([month, count]) => ({ month, count }));
  }

  private cacheNvdItems(items: NvdCveItem[]): void {
    if (items.length === 0) return;
    const next = new Map(this.nvdCacheSubject.value);
    for (const item of items) {
      next.set(item.id, item);
    }
    this.nvdCacheSubject.next(next);
  }

  private parseNvdItem(cve: any): NvdCveItem {
    const metrics = cve.metrics ?? {};
    const cvssData = metrics.cvssMetricV31?.[0]?.cvssData
      ?? metrics.cvssMetricV30?.[0]?.cvssData
      ?? metrics.cvssMetricV2?.[0]?.cvssData
      ?? null;

    const cwes: string[] = [];
    for (const w of (cve.weaknesses ?? [])) {
      for (const d of (w.description ?? [])) {
        if (d.value && d.value !== 'NVD-CWE-noinfo' && d.value !== 'NVD-CWE-Other') {
          cwes.push(d.value);
        } else if (d.value) {
          cwes.push('CWE-' + d.value.replace('NVD-', ''));
        }
      }
    }

    const cpes: string[] = [];
    for (const config of (cve.configurations ?? [])) {
      for (const node of (config.nodes ?? [])) {
        for (const match of (node.cpeMatch ?? [])) {
          if (match.vulnerable) cpes.push(match.criteria);
        }
      }
    }

    const mappedAttackIds = this.mapCwesToAttackIds(cwes);
    const kevEntry = this.kevMapSubject.value.get(cve.id);

    return {
      id: cve.id,
      description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? '',
      cvssScore: cvssData?.baseScore ?? null,
      cvssVector: cvssData?.vectorString ?? null,
      severity: (cvssData?.baseSeverity ?? 'UNKNOWN') as NvdCveItem['severity'],
      cwes,
      cpes: cpes.slice(0, 20),
      published: cve.published ?? '',
      lastModified: cve.lastModified ?? '',
      references: (cve.references ?? []).slice(0, 10).map((r: any) => ({ url: r.url, tags: r.tags ?? [] })),
      mappedAttackIds,
      isKev: !!kevEntry,
      kevDateAdded: kevEntry?.dateAdded,
      kevDueDate: kevEntry?.dueDate,
      kevVendorProject: kevEntry?.vendorProject,
      kevProduct: kevEntry?.product,
      kevKnownRansomware: kevEntry?.knownRansomwareCampaignUse === 'Known',
    };
  }
}
