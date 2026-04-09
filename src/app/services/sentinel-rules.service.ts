// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';

export interface SentinelRule {
  filename: string;
  url: string;
}

@Injectable({ providedIn: 'root' })
export class SentinelRulesService {
  private directCounts = new Map<string, number>();
  private rulesMap = new Map<string, SentinelRule[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  private loadRequested = false;

  constructor(private http: HttpClient) {}

  /** Load on demand - only fetches once. */
  loadOnDemand(): void {
    if (this.loadRequested) return;
    this.loadRequested = true;
    this.http
      .get<any>('https://api.github.com/repos/edoardogerosa/sentinel-attack/git/trees/master?recursive=1')
      .pipe(catchError(() => of(null)))
      .subscribe((tree: any) => {
        if (tree?.tree) {
          const techRegex = /T(\d{4}(?:\.\d{3})?)/;
          let total = 0;
          for (const item of tree.tree) {
            if (item.type !== 'blob') continue;
            const path: string = item.path ?? '';
            if (!path.endsWith('.json') && !path.endsWith('.yaml') && !path.endsWith('.yml')) continue;
            const match = path.match(techRegex);
            if (!match) continue;
            const id = 'T' + match[1];
            const segments = path.split('/');
            const filename = segments[segments.length - 1];
            const url = `https://github.com/edoardogerosa/sentinel-attack/blob/master/${path}`;
            const rule: SentinelRule = { filename, url };
            this.directCounts.set(id, (this.directCounts.get(id) ?? 0) + 1);
            if (!this.rulesMap.has(id)) {
              this.rulesMap.set(id, []);
            }
            this.rulesMap.get(id)!.push(rule);
            total++;
          }
          this.totalSubject.next(total);
          this.coveredSubject.next(this.directCounts.size);
        }
        this.loadedSubject.next(true);
      });
  }

  getRuleCount(attackId: string): number {
    const direct = this.directCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.directCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  getRulesForTechnique(attackId: string): SentinelRule[] {
    return this.rulesMap.get(attackId) ?? [];
  }
}
