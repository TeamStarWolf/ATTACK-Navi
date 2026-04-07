// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, of } from 'rxjs';

export interface M365Control {
  controlId: string;      // capability_id e.g. "EID-CA-E3"
  description: string;    // capability_description
  group: string;          // "entra-id", "defender", "purview", etc.
  scoreCategory: string;  // "protect", "detect", "respond"
  scoreValue: string;     // "significant", "partial", "minimal"
}

@Injectable({ providedIn: 'root' })
export class M365ControlsService {
  private static readonly URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/m365/attack-16.1/m365-07.18.2025/enterprise/m365-07.18.2025_attack-16.1-enterprise.json';

  private byTechniqueId = new Map<string, M365Control[]>();
  private byGroup = new Map<string, M365Control[]>();

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
    this.http.get<any>(M365ControlsService.URL).pipe(
      catchError(err => {
        console.error('[M365ControlsService] Failed to load M365 Controls mapping:', err);
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
      const group = m.capability_group ?? '';
      const control: M365Control = {
        controlId: m.capability_id ?? '',
        description: m.capability_description ?? '',
        group,
        scoreCategory: m.score_category ?? '',
        scoreValue: m.score_value ?? '',
      };
      // Index by technique
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      // Dedup by controlId + scoreCategory within same technique
      if (!this.byTechniqueId.get(techId)!.some(
        c => c.controlId === control.controlId && c.scoreCategory === control.scoreCategory,
      )) {
        this.byTechniqueId.get(techId)!.push(control);
        count++;
      }
      // Index by group
      if (group) {
        if (!this.byGroup.has(group)) this.byGroup.set(group, []);
        if (!this.byGroup.get(group)!.some(c => c.controlId === control.controlId)) {
          this.byGroup.get(group)!.push(control);
        }
      }
    }
    this.totalSubject.next(count);
    this.coveredSubject.next(this.byTechniqueId.size);
  }

  getControlsForTechnique(attackId: string): M365Control[] {
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

  getByGroup(group: string): M365Control[] {
    return this.byGroup.get(group) ?? [];
  }

  getGroups(): string[] {
    return [...this.byGroup.keys()].sort();
  }

  getControlCount(attackId: string): number {
    return this.getControlsForTechnique(attackId).length;
  }

  /** Heat score for heatmap: count of unique controls mapped to a technique. */
  getHeatScore(attackId: string): number {
    return this.getControlCount(attackId);
  }
}
