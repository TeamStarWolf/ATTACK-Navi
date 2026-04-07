// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, of } from 'rxjs';

export interface CsaCcmControl {
  controlId: string;      // capability_id e.g. "STA-16"
  description: string;    // capability_description
  mappingType: string;     // "mitigates"
  scoreCategory: string;  // "protect", "detect", "respond"
  scoreValue: string;     // "significant", "partial", "minimal"
}

@Injectable({ providedIn: 'root' })
export class CsaCcmService {
  private static readonly URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/csa_ccm/attack-17.1/csa_ccm-4.1/enterprise/csa_ccm-4.1_attack-17.1-enterprise.json';

  private byTechniqueId = new Map<string, CsaCcmControl[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any>(CsaCcmService.URL).pipe(
      catchError(err => {
        console.error('[CsaCcmService] Failed to load CSA CCM mapping:', err);
        return of(null);
      }),
    ).subscribe(data => {
      if (data) {
        this.parseAndIndex(data);
      }
      this.loadedSubject.next(true);
    });
  }

  private parseAndIndex(data: any): void {
    const mappings = data?.mapping_objects ?? [];
    let count = 0;
    for (const m of mappings) {
      if (!m.attack_object_id) continue;
      const techId = m.attack_object_id as string;
      const control: CsaCcmControl = {
        controlId: m.capability_id ?? '',
        description: m.capability_description ?? '',
        mappingType: m.mapping_type ?? 'mitigates',
        scoreCategory: m.score_category ?? '',
        scoreValue: m.score_value ?? '',
      };
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      // Dedup by controlId + scoreCategory
      if (!this.byTechniqueId.get(techId)!.some(
        c => c.controlId === control.controlId && c.scoreCategory === control.scoreCategory,
      )) {
        this.byTechniqueId.get(techId)!.push(control);
        count++;
      }
    }
    this.totalSubject.next(count);
    this.coveredSubject.next(this.byTechniqueId.size);
  }

  getControlsForTechnique(attackId: string): CsaCcmControl[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    if (attackId.includes('.')) return direct;
    // Include subtechnique controls for parent
    const prefix = attackId + '.';
    const fromSubs = [...this.byTechniqueId.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .flatMap(([, v]) => v);
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(c => {
      const key = c.controlId + ':' + c.scoreCategory;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  getControlCount(attackId: string): number {
    return this.getControlsForTechnique(attackId).length;
  }

  /** Heat score for heatmap: count of unique controls mapped to a technique. */
  getHeatScore(attackId: string): number {
    return this.getControlCount(attackId);
  }
}
