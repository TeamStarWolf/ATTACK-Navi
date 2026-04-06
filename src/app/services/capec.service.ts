// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { of } from 'rxjs';
import { retryWithBackoff } from '../utils/retry';

export interface CapecEntry {
  id: string;           // e.g. "CAPEC-112"
  name: string;
  description: string;
  likelihood: string;   // e.g. "High", "Medium", "Low"
  severity: string;     // e.g. "High" (impact severity)
  attackIds: string[];  // ATT&CK technique IDs
  cweIds: string[];     // CWE IDs this CAPEC is related to
  url: string;          // link to CAPEC entry on capec.mitre.org
}

@Injectable({ providedIn: 'root' })
export class CapecService {
  // Full CAPEC 3.x STIX bundle from MITRE CTI repo
  private static readonly URL =
    'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json';

  private byTechniqueId = new Map<string, CapecEntry[]>(); // ATT&CK ID → CAPEC[]
  private byCweId = new Map<string, CapecEntry[]>();        // CWE ID → CAPEC[]

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  /** Total number of CAPEC→ATT&CK technique links indexed. */
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Number of unique ATT&CK techniques that have ≥1 CAPEC entry. */
  covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any>(CapecService.URL).pipe(
      retryWithBackoff(),
      catchError(() => of({ objects: [] })),
    ).subscribe(data => {
      this.parseAndIndex(data);
    });
  }

  private parseAndIndex(data: any): void {
    const objects: any[] = data?.objects ?? [];
    let linkCount = 0;

    for (const obj of objects) {
      if (obj.type !== 'attack-pattern') continue;
      const refs: any[] = obj.external_references ?? [];

      // Find the CAPEC ID for this entry
      const capecRef = refs.find(r => r.source_name === 'capec');
      if (!capecRef?.external_id) continue;
      const capecId: string = capecRef.external_id; // e.g. "CAPEC-112"

      // Find ATT&CK technique references (CAPEC uses source_name "ATTACK")
      const attackIds: string[] = refs
        .filter(r => r.source_name === 'ATTACK' || r.source_name === 'mitre-attack')
        .map(r => (r.external_id as string)?.trim())
        .filter(id => id && /^T\d{4}/.test(id));

      if (!attackIds.length) continue;

      // CWE references
      const cweIds: string[] = refs
        .filter(r => r.source_name === 'cwe')
        .map(r => (r.external_id as string)?.trim())
        .filter(Boolean);

      const numericId = capecId.replace('CAPEC-', '');

      const entry: CapecEntry = {
        id: capecId,
        name: obj.name ?? '',
        description: this.extractDescription(obj.description ?? ''),
        likelihood: obj.x_capec_likelihood_of_attack ?? '',
        severity: obj.x_capec_typical_severity ?? '',
        attackIds,
        cweIds,
        url: `https://capec.mitre.org/data/definitions/${numericId}.html`,
      };

      // Index by ATT&CK technique
      for (const techId of attackIds) {
        if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
        if (!this.byTechniqueId.get(techId)!.some(e => e.id === capecId)) {
          this.byTechniqueId.get(techId)!.push(entry);
          linkCount++;
        }
      }

      // Index by CWE
      for (const cweId of cweIds) {
        if (!this.byCweId.has(cweId)) this.byCweId.set(cweId, []);
        if (!this.byCweId.get(cweId)!.some(e => e.id === capecId)) {
          this.byCweId.get(cweId)!.push(entry);
        }
      }
    }

    this.totalSubject.next(linkCount);
    this.coveredSubject.next(this.byTechniqueId.size);
    this.loadedSubject.next(true);
  }

  /** Strip markdown-style formatting from CAPEC descriptions. */
  private extractDescription(raw: string): string {
    // CAPEC descriptions use markdown-like format — trim to first paragraph
    const plain = raw
      .replace(/#+\s*/g, '')         // headings
      .replace(/\*\*([^*]+)\*\*/g, '$1') // bold
      .replace(/\*([^*]+)\*/g, '$1')     // italic
      .trim();
    const firstPara = plain.split(/\n\n/)[0]?.trim() ?? plain;
    return firstPara.length > 500 ? firstPara.slice(0, 500) + '…' : firstPara;
  }

  getCapecForTechnique(attackId: string): CapecEntry[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    // For parent techniques, also include subtechnique CAPEC entries (roll up)
    if (attackId.includes('.')) return direct;
    const prefix = attackId + '.';
    const fromSubs = [...this.byTechniqueId.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .flatMap(([, v]) => v);
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(e => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    });
  }

  getCapecCount(attackId: string): number {
    return this.getCapecForTechnique(attackId).length;
  }

  getCapecForCwe(cweId: string): CapecEntry[] {
    return this.byCweId.get(cweId) ?? [];
  }
}
