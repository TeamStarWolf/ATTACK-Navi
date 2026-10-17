// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, forkJoin, defer, TimeoutError } from 'rxjs';
import { map, catchError, timeout } from 'rxjs/operators';
import { SourceRegistryService } from './source-registry.service';

/** How long the EPSS availability check waits for an answer. */
export const EPSS_CHECK_TIMEOUT_MS = 8000;

export interface EpssScore {
  cveId: string;
  epss: number;       // 0-1 probability of exploitation in next 30 days
  percentile: number; // 0-1 percentile rank among all CVEs
  date: string;       // YYYY-MM-DD
}

@Injectable({ providedIn: 'root' })
export class EpssService {
  private readonly API = 'https://api.first.org/data/v1/epss';
  private cache = new Map<string, EpssScore>();

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {}

  /**
   * A real availability check for the EPSS API (E1.3; it replaces a hard-coded "up"):
   * one small GET (`limit=1`) with a timeout. The outcome lands on the 'epss'
   * SourceRecord: 'loaded' when the API answers with a score, 'empty' when it answers
   * with none, 'failed' with the reason on an error or no answer in time. Emits true
   * only when the API answered with data. A record that already holds data (scores
   * fetched earlier this session) is not checked again.
   */
  checkAvailability(): Observable<boolean> {
    return defer(() => {
      if (this.sources.hasData('epss')) return of(true);
      this.sources.begin('epss');
      return this.http.get<any>(`${this.API}?limit=1`).pipe(
        timeout(EPSS_CHECK_TIMEOUT_MS),
        map(response => {
          const answered = Array.isArray(response?.data) && response.data.length > 0;
          this.sources.succeed('epss', answered ? null : 0);
          return answered;
        }),
        catchError(err => {
          this.sources.fail(
            'epss',
            err instanceof TimeoutError ? `no answer within ${EPSS_CHECK_TIMEOUT_MS / 1000} s from ${this.API}` : err,
          );
          return of(false);
        }),
      );
    });
  }

  /** Fetch EPSS scores for a batch of CVE IDs. Returns cached results immediately.
   *  Batches into groups of 100 to stay within API limits. */
  fetchScores(cveIds: string[]): Observable<Map<string, EpssScore>> {
    const toFetch = cveIds.filter(id => !this.cache.has(id));

    if (toFetch.length === 0) {
      return of(this.buildResultMap(cveIds));
    }

    // Batch into groups of 100
    const batches: string[][] = [];
    for (let i = 0; i < toFetch.length; i += 100) {
      batches.push(toFetch.slice(i, i + 100));
    }

    // A failed batch is recorded as failed in the source registry. Callers still get the
    // scores that did arrive; a CVE missing from the map is "unknown", not "no score".
    this.sources.begin('epss');
    let failure: unknown = null;
    const requests = batches.map(batch =>
      this.http.get<any>(`${this.API}?cve=${batch.join(',')}`).pipe(
        catchError(err => {
          failure = err;
          return of({ data: [] });
        })
      )
    );

    return forkJoin(requests).pipe(
      map(responses => {
        if (failure) this.sources.fail('epss', failure);
        else this.sources.succeed('epss', null);
        for (const response of responses) {
          for (const item of (response?.data ?? [])) {
            const score: EpssScore = {
              cveId: item.cve,
              epss: parseFloat(item.epss ?? '0'),
              percentile: parseFloat(item.percentile ?? '0'),
              date: item.date ?? '',
            };
            this.cache.set(score.cveId, score);
          }
        }
        return this.buildResultMap(cveIds);
      })
    );
  }

  private buildResultMap(cveIds: string[]): Map<string, EpssScore> {
    const result = new Map<string, EpssScore>();
    for (const id of cveIds) {
      const score = this.cache.get(id);
      if (score) result.set(id, score);
    }
    return result;
  }

  /** Get a cached EPSS score synchronously (returns null if not yet fetched) */
  getScore(cveId: string): EpssScore | null {
    return this.cache.get(cveId) ?? null;
  }

  /** Returns a color for EPSS probability: red for high, green for low */
  getEpssColor(epss: number): string {
    if (epss >= 0.5) return '#d32f2f';
    if (epss >= 0.2) return '#f57c00';
    if (epss >= 0.05) return '#ffa000';
    return '#388e3c';
  }

  /** Returns risk label for EPSS */
  getEpssLabel(epss: number): string {
    if (epss >= 0.5) return 'CRITICAL';
    if (epss >= 0.2) return 'HIGH';
    if (epss >= 0.05) return 'MEDIUM';
    return 'LOW';
  }

  /** Format EPSS as percentage string */
  formatEpss(epss: number): string {
    if (epss >= 0.01) return `${(epss * 100).toFixed(1)}%`;
    return `${(epss * 100).toFixed(2)}%`;
  }
}
