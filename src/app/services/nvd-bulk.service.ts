import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, of, timer, switchMap } from 'rxjs';
import { filter, take } from 'rxjs/operators';
import { AttackCveService } from './attack-cve.service';
import { SettingsService } from './settings.service';
import { CWE_TO_ATTACK } from './cve.service';

/**
 * Loads a pre-computed CVE-to-ATT&CK technique mapping (every CVE in NVD
 * mapped via CWE), then supplements with a 120-day live API fetch for
 * the very latest CVEs.
 */
@Injectable({ providedIn: 'root' })
export class NvdBulkService {
  private supplementaryMap = new Map<string, Set<string>>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  covered$ = this.coveredSubject.asObservable();

  constructor(
    private http: HttpClient,
    private attackCveService: AttackCveService,
    private settingsService: SettingsService,
  ) {
    // Load pre-computed full mapping first, then supplement with live API
    this.http.get<Record<string, string[]>>('assets/data/cve-technique-map.json')
      .pipe(catchError(() => of(null)))
      .subscribe(data => {
        if (data) {
          for (const [attackId, cveIds] of Object.entries(data)) {
            const set = this.supplementaryMap.get(attackId) ?? new Set<string>();
            for (const cveId of cveIds) set.add(cveId);
            this.supplementaryMap.set(attackId, set);
          }
          this.totalSubject.next(this.countTotalCves());
          this.coveredSubject.next(this.supplementaryMap.size);
          this.loadedSubject.next(true);
        }
        // Then supplement with live 120-day fetch for the very latest CVEs
        this.attackCveService.loaded$.pipe(
          filter(loaded => loaded),
          take(1),
        ).subscribe(() => {
          this.fetchAll();
        });
      });
  }

  getCveCountForTechnique(attackId: string): number {
    return this.supplementaryMap.get(attackId)?.size ?? 0;
  }

  getCvesForTechnique(attackId: string): string[] {
    return [...(this.supplementaryMap.get(attackId) ?? [])];
  }

  private fetchAll(): void {
    const now = new Date();
    const past = new Date(now.getTime() - 120 * 24 * 60 * 60 * 1000);
    const startDate = past.toISOString().slice(0, 10) + 'T00:00:00.000';
    const endDate = now.toISOString().slice(0, 10) + 'T23:59:59.999';
    this.fetchPage(0, startDate, endDate);
  }

  private fetchPage(startIndex: number, startDate: string, endDate: string): void {
    const apiKey = this.settingsService.current.nvdApiKey;
    const delayMs = apiKey ? 200 : 500;

    let url = `https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=${startDate}&lastModEndDate=${endDate}&resultsPerPage=2000&startIndex=${startIndex}`;
    if (apiKey) {
      url += `&apiKey=${encodeURIComponent(apiKey)}`;
    }

    this.http.get<any>(url).pipe(
      catchError(() => of(null)),
    ).subscribe(data => {
      if (!data) {
        this.loadedSubject.next(true);
        return;
      }

      const totalResults: number = data.totalResults ?? 0;
      const vulnerabilities: any[] = data.vulnerabilities ?? [];

      this.processPage(vulnerabilities);
      this.totalSubject.next(this.countTotalCves());
      this.coveredSubject.next(this.supplementaryMap.size);

      const nextIndex = startIndex + 2000;
      if (nextIndex < totalResults) {
        // Delay between pages to respect rate limits
        timer(delayMs).pipe(
          switchMap(() => of(null)),
        ).subscribe(() => {
          this.fetchPage(nextIndex, startDate, endDate);
        });
      } else {
        this.loadedSubject.next(true);
      }
    });
  }

  private processPage(vulnerabilities: any[]): void {
    for (const entry of vulnerabilities) {
      const cve = entry?.cve;
      if (!cve) continue;

      const cveId: string = cve.id ?? '';
      if (!cveId.startsWith('CVE-')) continue;

      // Deduplicate: skip CVEs already in AttackCveService
      if (this.attackCveService.getMappingForCve(cveId)) continue;

      // Extract CWE IDs from weaknesses
      const weaknesses: any[] = cve.weaknesses ?? [];
      const cweIds = new Set<string>();
      for (const w of weaknesses) {
        const descriptions: any[] = w.description ?? [];
        for (const d of descriptions) {
          const val: string = d.value ?? '';
          if (val.startsWith('CWE-') && val !== 'CWE-noinfo' && val !== 'CWE-Other') {
            cweIds.add(val);
          }
        }
      }

      // Map each CWE to ATT&CK technique IDs
      for (const cweId of cweIds) {
        const attackIds = CWE_TO_ATTACK[cweId];
        if (!attackIds) continue;
        for (const attackId of attackIds) {
          if (!this.supplementaryMap.has(attackId)) {
            this.supplementaryMap.set(attackId, new Set());
          }
          this.supplementaryMap.get(attackId)!.add(cveId);
        }
      }
    }
  }

  private countTotalCves(): number {
    const allCves = new Set<string>();
    for (const cveSet of this.supplementaryMap.values()) {
      for (const cve of cveSet) {
        allCves.add(cve);
      }
    }
    return allCves.size;
  }
}
