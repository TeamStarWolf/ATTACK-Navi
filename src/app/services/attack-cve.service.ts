// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { retryWithBackoff } from '../utils/retry';

export interface CveAttackMapping {
  cveId: string;
  description: string;              // capability_description
  primaryImpact: string[];           // T#### IDs
  secondaryImpact: string[];         // T#### IDs
  exploitationTechnique: string[];   // T#### IDs
  capabilityGroup: string;           // "xxe", "sql_injection", "buffer_overflow", etc.
  comments: string[];                // analyst reasoning per mapping
  references: string[];              // source URLs
  phase: string;
  source: 'ctid-csv' | 'ctid-kev';  // which dataset this came from
}

@Injectable({ providedIn: 'root' })
export class AttackCveService {
  // CTID curated ATT&CK→CVE mapping (839 entries, older CVEs)
  private static readonly CSV_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv';

  // CTID KEV→ATT&CK mapping (1,183 entries — all CISA KEV CVEs mapped to ATT&CK)
  private static readonly KEV_CTID_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json';

  private byTechniqueId = new Map<string, CveAttackMapping[]>();
  private byCveId = new Map<string, CveAttackMapping>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Number of unique ATT&CK techniques that have ≥1 CVE mapping. */
  covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    forkJoin({
      csv: this.http.get(AttackCveService.CSV_URL, { responseType: 'text' }).pipe(
        retryWithBackoff(),
        catchError(() => of('')),
      ),
      kev: this.http.get<any>(AttackCveService.KEV_CTID_URL).pipe(
        retryWithBackoff(),
        catchError(() => of({ mapping_objects: [] })),
      ),
    }).subscribe(({ csv, kev }) => {
      if (csv) this.parseAndIndexCsv(csv);
      this.parseAndIndexKevJson(kev);
      this.totalSubject.next(this.byCveId.size);
      this.coveredSubject.next(this.byTechniqueId.size);
      this.loadedSubject.next(true);
    });
  }

  private parseAndIndexCsv(csv: string): void {
    const lines = csv.replace(/\r/g, '').split('\n').slice(1);

    for (const line of lines) {
      if (!line.trim()) continue;
      const parts = line.split(',');
      if (parts.length < 4) continue;

      const cveId = parts[0].trim();
      if (!cveId.startsWith('CVE-')) continue;

      const parseIds = (s: string) =>
        s.split(';').map(x => x.trim()).filter(x => /^T\d{4}/.test(x));

      const mapping: CveAttackMapping = {
        cveId,
        description: '',
        primaryImpact: parseIds(parts[1] ?? ''),
        secondaryImpact: parseIds(parts[2] ?? ''),
        exploitationTechnique: parseIds(parts[3] ?? ''),
        capabilityGroup: '',
        comments: [],
        references: [],
        phase: parts[5]?.trim() ?? '',
        source: 'ctid-csv',
      };

      this.indexMapping(mapping);
    }
  }

  /** Parse CTID mappings-explorer KEV JSON.
   *  Each mapping_object has a single CVE→technique link with a mapping_type.
   *  We group by CVE so the existing CveAttackMapping shape is preserved,
   *  and we now preserve comments, capability_description, capability_group,
   *  and references from each mapping_object.
   */
  private parseAndIndexKevJson(data: any): void {
    const objects: any[] = data?.mapping_objects ?? [];
    // Group by CVE first so we can build a CveAttackMapping per CVE
    const byCve = new Map<string, {
      primary: string[]; secondary: string[]; exploitation: string[];
      description: string; capabilityGroup: string;
      comments: string[]; references: string[];
    }>();

    for (const obj of objects) {
      const cveId: string = obj.capability_id ?? '';
      const techId: string = obj.attack_object_id ?? '';
      const mtype: string = obj.mapping_type ?? '';
      if (!cveId.startsWith('CVE-') || !/^T\d{4}/.test(techId)) continue;

      if (!byCve.has(cveId)) {
        byCve.set(cveId, {
          primary: [], secondary: [], exploitation: [],
          description: '', capabilityGroup: '', comments: [], references: [],
        });
      }
      const entry = byCve.get(cveId)!;

      // Collect capability_description (use first non-empty one per CVE)
      const capDesc: string = obj.capability_description ?? '';
      if (capDesc && !entry.description) {
        entry.description = capDesc;
      }

      // Collect capability_group
      const capGroup: string = obj.capability_group ?? '';
      if (capGroup && !entry.capabilityGroup) {
        entry.capabilityGroup = capGroup;
      }

      // Collect comments (analyst rationale per mapping_object)
      const comment: string = obj.comments ?? '';
      if (comment && !entry.comments.includes(comment)) {
        entry.comments.push(comment);
      }

      // Collect references (source URLs from each mapping_object)
      const refs: any[] = obj.references ?? [];
      for (const ref of refs) {
        const url = typeof ref === 'string' ? ref : (ref?.url ?? ref?.source ?? '');
        if (url && !entry.references.includes(url)) {
          entry.references.push(url);
        }
      }

      if (mtype === 'primary_impact' && !entry.primary.includes(techId)) {
        entry.primary.push(techId);
      } else if (mtype === 'secondary_impact' && !entry.secondary.includes(techId)) {
        entry.secondary.push(techId);
      } else if (mtype === 'exploitation_technique' && !entry.exploitation.includes(techId)) {
        entry.exploitation.push(techId);
      } else if (
        mtype !== 'primary_impact' && mtype !== 'secondary_impact' && mtype !== 'exploitation_technique'
        && !entry.primary.includes(techId)
      ) {
        entry.primary.push(techId);
      }
    }

    for (const [cveId, entry] of byCve) {
      // If CVE already indexed from CSV, merge technique IDs and metadata in
      const existing = this.byCveId.get(cveId);
      if (existing) {
        const addIfNew = (arr: string[], id: string) => { if (!arr.includes(id)) arr.push(id); };
        entry.primary.forEach(id => addIfNew(existing.primaryImpact, id));
        entry.secondary.forEach(id => addIfNew(existing.secondaryImpact, id));
        entry.exploitation.forEach(id => addIfNew(existing.exploitationTechnique, id));
        // Merge metadata
        if (!existing.description && entry.description) existing.description = entry.description;
        if (!existing.capabilityGroup && entry.capabilityGroup) existing.capabilityGroup = entry.capabilityGroup;
        entry.comments.forEach(c => addIfNew(existing.comments, c));
        entry.references.forEach(r => addIfNew(existing.references, r));
        // Re-index the updated mapping
        const allTechs = [
          ...new Set([
            ...existing.primaryImpact,
            ...existing.secondaryImpact,
            ...existing.exploitationTechnique,
          ]),
        ];
        for (const techId of allTechs) {
          if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
          if (!this.byTechniqueId.get(techId)!.some(m => m.cveId === cveId)) {
            this.byTechniqueId.get(techId)!.push(existing);
          }
        }
      } else {
        const mapping: CveAttackMapping = {
          cveId,
          description: entry.description,
          primaryImpact: entry.primary,
          secondaryImpact: entry.secondary,
          exploitationTechnique: entry.exploitation,
          capabilityGroup: entry.capabilityGroup,
          comments: entry.comments,
          references: entry.references,
          phase: '',
          source: 'ctid-kev',
        };
        this.indexMapping(mapping);
      }
    }
  }

  private indexMapping(mapping: CveAttackMapping): void {
    this.byCveId.set(mapping.cveId, mapping);
    const allTechs = [
      ...new Set([
        ...mapping.primaryImpact,
        ...mapping.secondaryImpact,
        ...mapping.exploitationTechnique,
      ]),
    ];
    for (const techId of allTechs) {
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      if (!this.byTechniqueId.get(techId)!.some(m => m.cveId === mapping.cveId)) {
        this.byTechniqueId.get(techId)!.push(mapping);
      }
    }
  }

  getCvesForTechnique(attackId: string): CveAttackMapping[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    const prefix = attackId + '.';
    const fromSubs = !attackId.includes('.')
      ? [...this.byTechniqueId.entries()]
          .filter(([k]) => k.startsWith(prefix))
          .flatMap(([, v]) => v)
      : [];
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(m => {
      if (seen.has(m.cveId)) return false;
      seen.add(m.cveId);
      return true;
    });
  }

  getMappingForCve(cveId: string): CveAttackMapping | undefined {
    return this.byCveId.get(cveId);
  }

  isCveMapped(cveId: string): boolean {
    return this.byCveId.has(cveId);
  }

  getExploitCvesForTechnique(attackId: string): string[] {
    return this.getCvesForTechnique(attackId)
      .filter(m => m.exploitationTechnique.includes(attackId))
      .map(m => m.cveId);
  }

  /** KEV-sourced CVEs only (from CTID KEV JSON). */
  getKevCvesForTechnique(attackId: string): CveAttackMapping[] {
    return this.getCvesForTechnique(attackId).filter(m => m.source === 'ctid-kev');
  }

  /** Search CVEs by ID, description, or capability group. Returns up to 50 results. */
  searchCves(query: string): CveAttackMapping[] {
    if (!query || query.length < 2) return [];
    const ql = query.toLowerCase();
    const results: CveAttackMapping[] = [];
    for (const mapping of this.byCveId.values()) {
      if (results.length >= 50) break;
      if (
        mapping.cveId.toLowerCase().includes(ql) ||
        mapping.description.toLowerCase().includes(ql) ||
        mapping.capabilityGroup.toLowerCase().includes(ql) ||
        mapping.comments.some(c => c.toLowerCase().includes(ql))
      ) {
        results.push(mapping);
      }
    }
    return results;
  }

  /** Return all CTID-curated mappings (both CSV and KEV sources). */
  getAllCtidMappings(): CveAttackMapping[] {
    return Array.from(this.byCveId.values());
  }
}
