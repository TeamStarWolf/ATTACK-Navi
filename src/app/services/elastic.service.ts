// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';
import { retryWithBackoff } from '../utils/retry';

interface NavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
  }>;
}

const ELASTIC_LAYER_URL =
  'https://raw.githubusercontent.com/elastic/detection-rules/main/etc/attack-navigator-layer.json';

@Injectable({ providedIn: 'root' })
export class ElasticService {
  private directCounts = new Map<string, number>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadLive();
  }

  private loadLive(): void {
    this.http.get<NavigatorLayer>(ELASTIC_LAYER_URL)
      .pipe(retryWithBackoff(), catchError(() => of(null)))
      .subscribe(layer => {
        if (layer?.techniques?.length) {
          this.ingestLayer(layer);
        }
        this.loadedSubject.next(true);
      });
  }

  /** Ingest a Navigator layer JSON with techniques[].techniqueID and techniques[].score. */
  ingestLayer(layer: NavigatorLayer): void {
    this.directCounts.clear();
    let total = 0;
    let covered = 0;
    for (const entry of layer.techniques ?? []) {
      const id = entry.techniqueID;
      const score = entry.score ?? 0;
      if (!id || score <= 0) continue;
      this.directCounts.set(id, score);
      total += score;
      covered++;
    }
    this.totalSubject.next(total);
    this.coveredSubject.next(covered);
    this.loadedSubject.next(true);
  }

  /** Rule count for a technique, with parent technique rollup. */
  getRuleCount(attackId: string): number {
    if (this.directCounts.size === 0) return 0;
    const direct = this.directCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.directCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  /** Alias used by matrix heatmap. */
  getHeatScore(attackId: string): number {
    return this.getRuleCount(attackId);
  }
}
