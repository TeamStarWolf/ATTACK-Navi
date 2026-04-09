// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';

export interface EvtxSample {
  filename: string;
  url: string;
  tactic: string;
}

@Injectable({ providedIn: 'root' })
export class EvtxSamplesService {
  private samplesMap = new Map<string, EvtxSample[]>();

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
      .get<any>('https://api.github.com/repos/mdecrevoisier/EVTX-to-MITRE-Attack/git/trees/main?recursive=1')
      .pipe(catchError(() => of(null)))
      .subscribe((tree: any) => {
        if (tree?.tree) {
          const techRegex = /T(\d{4}(?:\.\d{3})?)/;
          let total = 0;
          for (const item of tree.tree) {
            if (item.type !== 'blob') continue;
            if (!item.path?.endsWith('.evtx') && !item.path?.endsWith('.xml') && !item.path?.endsWith('.json')) continue;
            const match = item.path.match(techRegex);
            if (!match) continue;
            const id = 'T' + match[1];
            // Extract tactic from path segments (e.g. "TA0001 - Initial Access/...")
            const segments = (item.path as string).split('/');
            let tactic = '';
            for (const seg of segments) {
              if (/^TA\d{4}/.test(seg) || /initial|execution|persistence|privilege|defense|credential|discovery|lateral|collection|exfiltration|command|impact|resource|reconnaissance/i.test(seg)) {
                tactic = seg.replace(/^TA\d{4}\s*-\s*/, '').trim();
                break;
              }
            }
            const filename = segments[segments.length - 1];
            const url = `https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/main/${item.path}`;
            const sample: EvtxSample = { filename, url, tactic };
            if (!this.samplesMap.has(id)) {
              this.samplesMap.set(id, []);
            }
            this.samplesMap.get(id)!.push(sample);
            total++;
          }
          this.totalSubject.next(total);
          this.coveredSubject.next(this.samplesMap.size);
        }
        this.loadedSubject.next(true);
      });
  }

  getSamplesForTechnique(attackId: string): EvtxSample[] {
    return this.samplesMap.get(attackId) ?? [];
  }

  getSampleCount(attackId: string): number {
    const direct = this.samplesMap.get(attackId)?.length ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, samples] of this.samplesMap) {
      if (id.startsWith(prefix)) sub += samples.length;
    }
    return direct + sub;
  }
}
