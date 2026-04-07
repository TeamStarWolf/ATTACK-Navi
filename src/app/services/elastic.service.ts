// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';


interface NavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
  }>;
}

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
    // Elastic no longer publishes a pre-built Navigator layer.
    // Scan the GitHub tree for .toml rule files and extract technique IDs.
    this.http.get<any>('https://api.github.com/repos/elastic/detection-rules/git/trees/main?recursive=1')
      .pipe(catchError(() => of(null)))
      .subscribe((tree: any) => {
        if (tree?.tree) {
          const counts = new Map<string, number>();
          const techRegex = /[Tt](1\d{3}(?:\.\d{3})?)/;
          for (const item of tree.tree) {
            if (item.path?.startsWith('rules/') && item.path?.endsWith('.toml')) {
              const match = item.path.match(techRegex);
              if (match) {
                const id = 'T' + match[1];
                counts.set(id, (counts.get(id) ?? 0) + 1);
              }
            }
          }
          if (counts.size > 0) {
            const layer: NavigatorLayer = { techniques: [] };
            for (const [id, score] of counts) {
              layer.techniques.push({ techniqueID: id, score });
            }
            this.ingestLayer(layer);
          }
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
