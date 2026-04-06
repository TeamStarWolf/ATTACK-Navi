// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';

export interface VerisAction {
  id: string;         // "action.hacking.variety.Brute force"
  description: string;
  category: string;   // Second segment capitalized: "hacking" → "Hacking"
  subcategory: string; // Third segment capitalized: "variety" → "Variety"
  label: string;      // Remaining segments joined: "Brute force"
  mappingType: string;
}

@Injectable({ providedIn: 'root' })
export class VerisService {
  private static readonly URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/veris/attack-16.1/veris-1.4.0/enterprise/veris-1.4.0_attack-16.1-enterprise.json';

  private byTechniqueId = new Map<string, VerisAction[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any>(VerisService.URL).subscribe({
      next: (data) => this.parseAndIndex(data),
      error: (err) => {
        console.error('[VerisService] Failed to load VERIS mapping:', err);
        this.loadedSubject.next(false);
      },
    });
  }

  private parseAndIndex(data: any): void {
    const mappings = data?.mapping_objects ?? [];
    let count = 0;
    for (const m of mappings) {
      if (!m.attack_object_id || !m.capability_id) continue;
      const techId = m.attack_object_id as string;
      const action = this.parseAction(m);
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      // Dedup by capability_id
      if (!this.byTechniqueId.get(techId)!.some(a => a.id === action.id)) {
        this.byTechniqueId.get(techId)!.push(action);
        count++;
      }
    }
    this.totalSubject.next(count);
    this.loadedSubject.next(true);
  }

  private parseAction(m: any): VerisAction {
    const capabilityId: string = m.capability_id ?? '';
    // Format: "action.hacking.variety.Brute force"
    // parts[0] = "action", parts[1] = "hacking", parts[2] = "variety", parts[3+] = label
    const parts = capabilityId.split('.');
    const category = parts.length > 1 ? this.capitalize(parts[1]) : '';
    const subcategory = parts.length > 2 ? this.capitalize(parts[2]) : '';
    const label = parts.length > 3 ? parts.slice(3).join('.') : capabilityId;

    return {
      id: capabilityId,
      description: m.capability_description ?? '',
      category,
      subcategory,
      label,
      mappingType: m.mapping_type ?? 'related-to',
    };
  }

  private capitalize(s: string): string {
    if (!s) return s;
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  getActionsForTechnique(attackId: string): VerisAction[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    if (attackId.includes('.')) return direct;
    // Include subtechnique actions for parent
    const prefix = attackId + '.';
    const fromSubs = [...this.byTechniqueId.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .flatMap(([, v]) => v);
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(a => {
      if (seen.has(a.id)) return false;
      seen.add(a.id);
      return true;
    });
  }
}
