// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';

export interface CisControl {
  id: string;          // "CIS 1.1"
  description: string; // long description
  group: string;       // "IG1" / "IG2" / "IG3" or empty
  mappingType: string; // "mitigates" or "detects"
}

@Injectable({ providedIn: 'root' })
export class CisControlsService {
  // NOTE: CIS Controls was removed from the CTID mappings-explorer repository as of ATT&CK v16.
  // No public JSON mapping compatible with the mappings-explorer format is currently available.
  // The service loads as empty/unavailable; update this URL when a new source is published.
  private static readonly URL: string | null = null;

  private byTechniqueId = new Map<string, CisControl[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    if (!CisControlsService.URL) {
      // No data source available — mark as loaded with empty dataset
      this.loadedSubject.next(true);
      return;
    }
    this.http.get<any>(CisControlsService.URL).subscribe({
      next: (data) => this.parseAndIndex(data),
      error: (err) => {
        console.error('[CisControlsService] Failed to load CIS Controls mapping:', err);
        this.loadedSubject.next(true);
      },
    });
  }

  private parseAndIndex(data: any): void {
    const mappings = data?.mapping_objects ?? [];
    let count = 0;
    for (const m of mappings) {
      if (!m.attack_object_id) continue;
      const techId = m.attack_object_id as string;
      // Extract IG group from comments or capability_group field
      const group = this.extractGroup(m);
      const control: CisControl = {
        id: m.capability_id ?? '',
        description: m.capability_description ?? '',
        group,
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

  private extractGroup(m: any): string {
    // Check explicit group field
    if (m.capability_group) return m.capability_group;
    // Try to extract "IG1" / "IG2" / "IG3" from comments
    const comments: string = m.comments ?? '';
    const igMatch = comments.match(/\bIG([123])\b/i);
    if (igMatch) return `IG${igMatch[1]}`;
    // Try "Implementation Group N"
    const igLong = comments.match(/Implementation\s+Group\s+([123])/i);
    if (igLong) return `IG${igLong[1]}`;
    return '';
  }

  getControlsForTechnique(attackId: string): CisControl[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    if (attackId.includes('.')) return direct;
    // Include subtechnique controls for parent
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
