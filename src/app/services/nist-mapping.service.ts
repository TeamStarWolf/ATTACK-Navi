// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';

export interface NistControl {
  id: string;          // e.g. "CM-03"
  description: string; // e.g. "Configuration Change Control"
  family: string;      // e.g. "CM" (2-letter family code)
  mappingType: string; // "mitigates"
}

@Injectable({ providedIn: 'root' })
export class NistMappingService {
  private static readonly URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json';

  private byTechniqueId = new Map<string, NistControl[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any>(NistMappingService.URL).subscribe({
      next: (data) => this.parseAndIndex(data),
      error: () => this.loadedSubject.next(false),
    });
  }

  private parseAndIndex(data: any): void {
    const mappings = data?.mapping_objects ?? [];
    let count = 0;
    for (const m of mappings) {
      if (m.status !== 'complete' || !m.attack_object_id) continue;
      const techId = m.attack_object_id as string;
      const control: NistControl = {
        id: m.capability_id,
        description: m.capability_description,
        family: m.capability_group ?? m.capability_id?.split('-')[0] ?? '',
        mappingType: m.mapping_type ?? 'mitigates',
      };
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      // Dedup by control ID
      if (!this.byTechniqueId.get(techId)!.some(c => c.id === control.id)) {
        this.byTechniqueId.get(techId)!.push(control);
        count++;
      }
    }
    this.totalSubject.next(count);
    this.loadedSubject.next(true);
  }

  getControlsForTechnique(attackId: string): NistControl[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    // Parent technique includes subtechnique controls too
    if (attackId.includes('.')) return direct;
    const prefix = attackId + '.';
    const fromSubs = [...this.byTechniqueId.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .flatMap(([, v]) => v);
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(c => {
      if (seen.has(c.id)) return false;
      seen.add(c.id);
      return true;
    });
  }

  getControlCount(attackId: string): number {
    return this.getControlsForTechnique(attackId).length;
  }
}
