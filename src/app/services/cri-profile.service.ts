import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';

export interface CriControl {
  id: string;          // e.g. "PR.IR-01.05"
  description: string; // e.g. "Implement additional safeguards..."
  function: string;    // e.g. "PR" (Protect)
  functionLabel: string; // e.g. "Protect"
  category: string;    // e.g. "PR.IR"
  mappingType: string; // e.g. "mitigates"
  url: string;         // Link to mappings-explorer page for this control
}

// Map CRI Profile function codes to human-readable labels
const FUNCTION_LABELS: Record<string, string> = {
  GV: 'Govern',
  ID: 'Identify',
  PR: 'Protect',
  DE: 'Detect',
  RS: 'Respond',
  RC: 'Recover',
};

@Injectable({ providedIn: 'root' })
export class CriProfileService {
  private static readonly URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/cri_profile/attack-16.1/cri_profile-v2.1/enterprise/cri_profile-v2.1_attack-16.1-enterprise.json';

  private static readonly EXPLORER_BASE =
    'https://center-for-threat-informed-defense.github.io/mappings-explorer/external/cri_profile/attack-16.1/domain-enterprise/cri_profile-v2.1';

  private byTechniqueId = new Map<string, CriControl[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Number of unique ATT&CK techniques that have ≥1 CRI Profile mapping. */
  covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any>(CriProfileService.URL).subscribe({
      next: (data) => this.parseAndIndex(data),
      error: (err) => {
        console.error('[CriProfileService] Failed to load CRI Profile mapping:', err);
        this.loadedSubject.next(true); // mark done even on failure
      },
    });
  }

  private parseAndIndex(data: any): void {
    const mappings = data?.mapping_objects ?? [];
    let count = 0;
    for (const m of mappings) {
      if (!m.attack_object_id || !m.capability_id) continue;
      const techId: string = m.attack_object_id;
      const control = this.parseControl(m);
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      // Dedup by control ID
      if (!this.byTechniqueId.get(techId)!.some(c => c.id === control.id)) {
        this.byTechniqueId.get(techId)!.push(control);
        count++;
      }
    }
    this.totalSubject.next(count);
    this.coveredSubject.next(this.byTechniqueId.size);
    this.loadedSubject.next(true);
  }

  private parseControl(m: any): CriControl {
    const id: string = m.capability_id ?? '';
    // CRI IDs like "PR.IR-01.05" — function is first two chars
    const funcCode = id.split('.')[0] ?? '';
    const category = id.includes('-') ? id.split('-')[0] : funcCode;
    const functionLabel = FUNCTION_LABELS[funcCode] ?? funcCode;

    return {
      id,
      description: m.capability_description ?? '',
      function: funcCode,
      functionLabel,
      category,
      mappingType: m.mapping_type ?? 'mitigates',
      url: `${CriProfileService.EXPLORER_BASE}/${encodeURIComponent(id)}/`,
    };
  }

  getControlsForTechnique(attackId: string): CriControl[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    if (attackId.includes('.')) return direct;
    // Include subtechnique controls for parent rollup
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

  /** Returns controls grouped by CRI function (GV, ID, PR, DE, RS, RC). */
  getGroupedControls(attackId: string): Map<string, CriControl[]> {
    const controls = this.getControlsForTechnique(attackId);
    const grouped = new Map<string, CriControl[]>();
    for (const c of controls) {
      if (!grouped.has(c.function)) grouped.set(c.function, []);
      grouped.get(c.function)!.push(c);
    }
    return grouped;
  }
}
