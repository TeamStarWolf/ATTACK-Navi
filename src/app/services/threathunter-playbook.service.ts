// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

interface PlaybookNavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
  }>;
}

const PLAYBOOK_LAYER_URLS = [
  'https://raw.githubusercontent.com/OTRF/ThreatHunter-Playbook/master/attack_navigator/ThreatHunter_Playbook.json',
  'https://raw.githubusercontent.com/OTRF/ThreatHunter-Playbook/master/docs/notebooks/attack_navigator_layer.json',
];

@Injectable({ providedIn: 'root' })
export class ThreatHunterPlaybookService {
  private playbookCounts = new Map<string, number>();
  private tacticMap = new Map<string, string>(); // techniqueID -> tactic shortname

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.tryUrl(0);
  }

  /** Try each URL in sequence until one succeeds. */
  private tryUrl(index: number): void {
    if (index >= PLAYBOOK_LAYER_URLS.length) return;
    this.http.get<PlaybookNavigatorLayer>(PLAYBOOK_LAYER_URLS[index]).pipe(
      catchError(() => of(null)),
    ).subscribe(layer => {
      if (layer?.techniques?.length) {
        this.ingestLayer(layer);
      } else {
        this.tryUrl(index + 1);
      }
    });
  }

  private ingestLayer(layer: PlaybookNavigatorLayer): void {
    this.playbookCounts.clear();
    this.tacticMap.clear();
    let total = 0;
    let covered = 0;
    for (const entry of layer.techniques ?? []) {
      const id = entry.techniqueID;
      const score = entry.score ?? 0;
      if (!id || score <= 0) continue;
      this.playbookCounts.set(id, score);
      if (entry.tactic) {
        this.tacticMap.set(id, entry.tactic);
      }
      total += score;
      covered++;
    }
    this.totalSubject.next(total);
    this.coveredSubject.next(covered);
    this.loadedSubject.next(true);
  }

  /** Playbook count for a technique (rolls up sub-technique counts). */
  getPlaybookCount(attackId: string): number {
    const direct = this.playbookCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.playbookCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  /** Build a URL to the ThreatHunter Playbook page for a technique. */
  getPlaybookUrl(attackId: string): string | null {
    if (this.playbookCounts.has(attackId) || this.getPlaybookCount(attackId) > 0) {
      // Use the tactic from layer data, or fall back to generic search
      const tactic = this.tacticMap.get(attackId);
      if (tactic) {
        return `https://threathunterplaybook.com/notebooks/${tactic}/${attackId}.html`;
      }
      // Fallback: link to the playbook search
      return `https://threathunterplaybook.com/search.html?q=${attackId}`;
    }
    return null;
  }

  /** Alias used by heatmap subsystem. */
  getHeatScore(attackId: string): number {
    return this.getPlaybookCount(attackId);
  }
}
