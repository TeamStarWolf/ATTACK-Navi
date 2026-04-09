// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { retryWithBackoff } from '../utils/retry';

export interface KillChainEntry {
  cveId: string;
  cwes: string[];
  capecs: string[];
  techniques: string[];
  defenses: string[];
}

@Injectable({ providedIn: 'root' })
export class Cve2CapecService {
  private static readonly BASE_URL =
    'https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/database';

  private byTechniqueId = new Map<string, KillChainEntry[]>();
  private byCveId = new Map<string, KillChainEntry>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  /** Total CVE→ATT&CK kill chain mappings indexed. */
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Unique ATT&CK techniques with ≥1 CVE2CAPEC kill chain. */
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    const currentYear = new Date().getFullYear();
    // Fetch current year + previous year for reasonable coverage
    const urls = [
      `${Cve2CapecService.BASE_URL}/CVE-${currentYear}.jsonl`,
      `${Cve2CapecService.BASE_URL}/CVE-${currentYear - 1}.jsonl`,
    ];

    forkJoin(
      urls.map(url =>
        this.http.get(url, { responseType: 'text' }).pipe(
          retryWithBackoff(),
          catchError(() => of('')),
        ),
      ),
    ).subscribe(results => {
      for (const text of results) {
        if (text) this.parseJsonl(text);
      }
      this.totalSubject.next(this.byCveId.size);
      this.coveredSubject.next(this.byTechniqueId.size);
      this.loadedSubject.next(true);
    });
  }

  private parseJsonl(text: string): void {
    const lines = text.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let parsed: Record<string, any>;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        continue;
      }

      for (const [cveId, data] of Object.entries(parsed)) {
        if (!cveId.startsWith('CVE-') || !data) continue;

        const techniques: string[] = (data.TECHNIQUES ?? [])
          .map((t: string) => t.trim())
          .filter((t: string) => /^T\d{4}/.test(t));

        if (techniques.length === 0) continue;

        const entry: KillChainEntry = {
          cveId,
          cwes: (data.CWE ?? []).map((s: string) => s.trim()).filter(Boolean),
          capecs: (data.CAPEC ?? []).map((s: string) => String(s).trim()).filter(Boolean),
          techniques,
          defenses: (data.DEFEND ?? []).map((s: string) => s.trim()).filter(Boolean),
        };

        this.byCveId.set(cveId, entry);

        for (const techId of techniques) {
          if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
          this.byTechniqueId.get(techId)!.push(entry);
        }
      }
    }
  }

  /** All CVE kill chains mapping to a given ATT&CK technique. */
  getChainForTechnique(attackId: string): KillChainEntry[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    if (attackId.includes('.')) return direct;
    // Roll up subtechnique chains for parent techniques
    const prefix = attackId + '.';
    const fromSubs = [...this.byTechniqueId.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .flatMap(([, v]) => v);
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(e => {
      if (seen.has(e.cveId)) return false;
      seen.add(e.cveId);
      return true;
    });
  }

  /** Full kill chain for a specific CVE. */
  getChainForCve(cveId: string): KillChainEntry | null {
    return this.byCveId.get(cveId) ?? null;
  }

  /** Count of CVE kill chains for heatmap scoring. */
  getChainCount(attackId: string): number {
    return this.getChainForTechnique(attackId).length;
  }

  /** Aggregated D3FEND defense IDs across all chains for a technique. */
  getDefensesForTechnique(attackId: string): string[] {
    const chains = this.getChainForTechnique(attackId);
    const seen = new Set<string>();
    for (const chain of chains) {
      for (const d of chain.defenses) seen.add(d);
    }
    return [...seen];
  }
}
