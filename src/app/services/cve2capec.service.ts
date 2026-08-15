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
    // Fetch current year + previous year for reasonable coverage.
    // Upstream ships gzip-compressed JSONL (database/CVE-<year>.jsonl.gz);
    // recent years decompress to hundreds of MB, beyond the browser's max
    // string length — so decompression and parsing are streamed line-by-line.
    const urls = [
      `${Cve2CapecService.BASE_URL}/CVE-${currentYear}.jsonl.gz`,
      `${Cve2CapecService.BASE_URL}/CVE-${currentYear - 1}.jsonl.gz`,
    ];

    forkJoin(
      urls.map(url =>
        this.http.get(url, { responseType: 'blob' }).pipe(
          retryWithBackoff(),
          catchError(() => of(null)),
        ),
      ),
    ).subscribe(async results => {
      for (const blob of results) {
        if (!blob || blob.size === 0) continue;
        try {
          await this.streamParseGzipJsonl(blob);
        } catch {
          // Corrupt payload or unsupported browser — skip this year file.
        }
      }
      this.totalSubject.next(this.byCveId.size);
      this.coveredSubject.next(this.byTechniqueId.size);
      this.loadedSubject.next(true);
    });
  }

  /** Stream-decompress a gzip JSONL blob and parse it line by line. */
  private async streamParseGzipJsonl(blob: Blob): Promise<void> {
    if (typeof DecompressionStream === 'undefined') return;
    const stream = blob
      .stream()
      .pipeThrough(new DecompressionStream('gzip'))
      .pipeThrough(new TextDecoderStream());
    const reader = stream.getReader();
    let buffer = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += value;
      let newline: number;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        this.parseJsonlLine(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
      }
    }
    this.parseJsonlLine(buffer);
  }

  /**
   * Upstream publishes bare numeric ids ("1027", "1562.003", CWE "79",
   * CAPEC "8") — normalize to the prefixed forms the rest of the app uses.
   * (The previous parser required a "T" prefix, so it indexed nothing.)
   */
  private static normalizeTechniqueId(raw: unknown): string | null {
    const s = String(raw).trim();
    if (/^T\d{4}(\.\d{3})?$/.test(s)) return s;
    if (/^\d{4}(\.\d{3})?$/.test(s)) return 'T' + s;
    return null;
  }

  private parseJsonlLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    let parsed: Record<string, any>;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return;
    }

    for (const [cveId, data] of Object.entries(parsed)) {
      if (!cveId.startsWith('CVE-') || !data) continue;

      const techniques: string[] = ((data as any).TECHNIQUES ?? [])
        .map((t: unknown) => Cve2CapecService.normalizeTechniqueId(t))
        .filter((t: string | null): t is string => t !== null);

      if (techniques.length === 0) continue;

      const entry: KillChainEntry = {
        cveId,
        cwes: ((data as any).CWE ?? [])
          .map((s: unknown) => String(s).trim())
          .filter(Boolean)
          .map((s: string) => (s.startsWith('CWE-') ? s : `CWE-${s}`)),
        capecs: ((data as any).CAPEC ?? [])
          .map((s: unknown) => String(s).trim())
          .filter(Boolean)
          .map((s: string) => (s.startsWith('CAPEC-') ? s : `CAPEC-${s}`)),
        techniques,
        defenses: ((data as any).DEFEND ?? []).map((s: unknown) => String(s).trim()).filter(Boolean),
      };

      this.byCveId.set(cveId, entry);

      for (const techId of techniques) {
        if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
        this.byTechniqueId.get(techId)!.push(entry);
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
