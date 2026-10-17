// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { SourceRegistryService } from './source-registry.service';

/** v2 asset schema: exact per-technique count + most-recent CVE id sample. */
interface CveMapEntryV2 {
  c: number;
  s: string[];
}

interface CveMapMetaV2 {
  source?: string;
  generated?: string;
  cveCount?: number;
  refCount?: number;
  sampleCap?: number;
}

/**
 * Historical CVE→ATT&CK technique index, generated from the CVE2CAPEC
 * pipeline (CVE → CWE → CAPEC → ATT&CK over MITRE-published data, all CVE
 * years). Replaces the previous NVD-scan supplement that mapped CVEs through
 * a generated CWE→technique table whose entries were largely unverifiable.
 * The bundled asset carries exact counts plus a capped sample of the most
 * recent CVE ids per technique (see scripts note in CHANGELOG).
 */
@Injectable({ providedIn: 'root' })
export class NvdBulkService {
  private counts = new Map<string, number>();
  private samples = new Map<string, string[]>();
  private meta: CveMapMetaV2 = {};

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  /** Unique CVEs with at least one derived technique mapping. */
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Techniques with at least one mapped CVE. */
  covered$ = this.coveredSubject.asObservable();

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {
    this.loadMap();
  }

  /** Load again after a failed or empty load: the data-health Retry (E1.3). */
  retry(): void {
    this.loadMap();
  }

  private loadMap(): void {
    this.sources.begin('cve-technique-map');
    this.http
      .get<Record<string, CveMapEntryV2 | CveMapMetaV2>>('assets/data/cve-technique-map.json')
      .subscribe({ next: data => {
        if (data) {
          for (const [key, value] of Object.entries(data)) {
            if (key === '__meta') {
              this.meta = value as CveMapMetaV2;
              continue;
            }
            const entry = value as CveMapEntryV2;
            if (typeof entry?.c !== 'number') continue;
            this.counts.set(key, entry.c);
            this.samples.set(key, entry.s ?? []);
          }
          this.totalSubject.next(this.meta.cveCount ?? this.counts.size);
          this.coveredSubject.next(this.counts.size);
        }
        this.sources.succeed('cve-technique-map', this.counts.size);
        if (this.counts.size > 0) this.loadedSubject.next(true);
      },
      // Recorded as failed; loaded$ stays false.
      error: err => this.sources.fail('cve-technique-map', err) });
  }

  /** Exact count of pipeline-mapped CVEs for a technique (subtechniques roll up). */
  getCveCountForTechnique(attackId: string): number {
    const direct = this.counts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.counts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  /** Most recent mapped CVE ids for a technique (capped sample, newest first). */
  getCvesForTechnique(attackId: string): string[] {
    return [...(this.samples.get(attackId) ?? [])];
  }

  /** Provenance of the bundled index (source pipeline + generation date). */
  getMeta(): CveMapMetaV2 {
    return { ...this.meta };
  }
}
